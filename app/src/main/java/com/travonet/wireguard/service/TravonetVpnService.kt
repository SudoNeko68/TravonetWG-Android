package com.travonet.wireguard.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import com.travonet.wireguard.MainActivity
import com.travonet.wireguard.R
import com.travonet.wireguard.model.TunnelMode
import com.travonet.wireguard.model.TunnelStatus
import com.travonet.wireguard.parser.WgConfigParser
import com.travonet.wireguard.repository.AppRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.travonet.backend.GoBackend

class TravonetVpnService : VpnService() {

    private val serviceScope = CoroutineScope(Dispatchers.IO)
    private val tunnelMutex = Mutex()
    private var startJob: Job? = null
    private var statsJob: Job? = null
    private var healthJob: Job? = null

    private var connectivityManager: ConnectivityManager? = null
    private var defaultNetworkCallback: ConnectivityManager.NetworkCallback? = null

    // The tunnel owned by *this* service instance. TunnelManager.vpnHandle is
    // shared with the UI and can already point at a newer instance; releasing
    // by the shared value would tear down a freshly started tunnel.
    private var activeHandle: Int = -1
    private var activePfd: ParcelFileDescriptor? = null
    @Volatile private var destroyed = false
    private var wakeLock: PowerManager.WakeLock? = null

    companion object {
        const val TAG = "TravonetVPN"
        const val ACTION_START = "com.travonet.wireguard.action.START_VPN"
        const val ACTION_STOP = "com.travonet.wireguard.action.STOP_VPN"
        const val EXTRA_PROFILE_ID = "profile_id"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "travonet_vpn_channel"
        private const val HANDSHAKE_TIMEOUT_MS = 45_000L
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_STOP) {
            stopTunnelAsync()
            return START_NOT_STICKY
        }

        if (action == ACTION_START) {
            val profileId = intent.getStringExtra(EXTRA_PROFILE_ID)
            val repository = AppRepository(this)
            val profile = repository.getProfiles().firstOrNull { it.id == profileId }
                ?: repository.getSelectedProfile()

            if (profile == null) {
                TunnelManager.updateState(TunnelStatus.ERROR, "Профиль не найден")
                stopSelf()
                return START_NOT_STICKY
            }

            // Immediately start foreground notification to satisfy Android Foreground Service watchdog
            startForegroundServiceNotification(profile.name, "Запуск...", "Подключение...")

            val strategy = repository.getSelectedStrategy()
            startJob?.cancel()
            startJob = serviceScope.launch {
                tunnelMutex.withLock {
                    startTunnelLocked(profile, strategy, 0)
                }
            }
        }

        return START_NOT_STICKY
    }

    private suspend fun startTunnelLocked(
        profile: com.travonet.wireguard.model.WgProfile,
        strategy: com.travonet.wireguard.model.EvasionStrategy,
        attempt: Int = 0
    ) {
        try {
            // Release only our own previous tunnel. A newer service instance
            // may already own TunnelManager.vpnHandle.
            releaseTunnelLocked()

            val parsed = WgConfigParser.parse(profile.rawConfig)
            val preparedConfig = WgConfigParser.prepareConfigForLaunch(profile, strategy)
            val resolvedConfig = WgConfigParser.resolveConfigEndpoints(preparedConfig)

            val builder = Builder()
                .setSession("TravonetWG - ${profile.name}")
                .setMtu(parsed.iface.mtu)
                .setBlocking(true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            // Add Addresses
            var hasIpv4 = false
            var hasIpv6 = false

            parsed.iface.addresses.forEach { addrStr ->
                try {
                    val parts = addrStr.split("/")
                    val ip = parts[0].trim()
                    val isV6 = ip.contains(":")
                    val prefix = if (parts.size > 1) parts[1].trim().toInt() else if (isV6) 128 else 32
                    builder.addAddress(ip, prefix)
                    if (isV6) hasIpv6 = true else hasIpv4 = true
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to parse address: $addrStr", e)
                }
            }

            if (!hasIpv4 && !hasIpv6) {
                builder.addAddress("172.16.0.2", 32)
                hasIpv4 = true
            }

            // Add Routes
            var routeCount = 0
            parsed.peers.forEach { peer ->
                peer.allowedIps.forEach { ipStr ->
                    try {
                        val parts = ipStr.split("/")
                        val ip = parts[0].trim()
                        val isV6 = ip.contains(":")
                        // Android VpnService does not allow adding an IPv6 route without an IPv6 address
                        if (isV6 && !hasIpv6) {
                            return@forEach
                        }
                        if (!isV6 && !hasIpv4) {
                            return@forEach
                        }
                        val prefix = if (parts.size > 1) parts[1].trim().toInt() else if (isV6) 128 else 32
                        builder.addRoute(ip, prefix)
                        routeCount++
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to parse allowed IP: $ipStr", e)
                    }
                }
            }

            if (routeCount == 0) {
                if (hasIpv4) builder.addRoute("0.0.0.0", 0)
                if (hasIpv6) builder.addRoute("::", 0)
            }

            builder.allowFamily(OsConstants.AF_INET)
            if (!hasIpv6) {
                builder.allowFamily(OsConstants.AF_INET6)
            }

            // Add DNS
            var dnsCount = 0
            parsed.iface.dnsServers.forEach { dnsStr ->
                try {
                    val dns = dnsStr.trim()
                    val isV6 = dns.contains(":")
                    if (isV6 && !hasIpv6) {
                        return@forEach
                    }
                    builder.addDnsServer(dns)
                    dnsCount++
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to add DNS: $dnsStr", e)
                }
            }

            if (dnsCount == 0) {
                builder.addDnsServer("1.1.1.1")
                builder.addDnsServer("8.8.8.8")
            }

            val currentPfd = builder.establish()
            if (currentPfd == null) {
                TunnelManager.updateState(TunnelStatus.ERROR, "Не удалось создать системный TUN интерфейс")
                stopSelf()
                return
            }
            activePfd = currentPfd
            val tunFd = currentPfd.detachFd()

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setUnderlyingNetworks(null)
            }
            registerNetworkCallback()

            // wgTurnOnProtected применяет VpnService.protect(fd) к каждому
            // UDP-сокету ещё до bind(), поэтому handshake не может уйти в tun
            // и зациклиться.
            val handle = GoBackend.wgTurnOnProtected(
                "wg0", tunFd, resolvedConfig, this@TravonetVpnService
            )

            // The start may have been superseded or cancelled while the blocking JNI call was running.
            if (!currentCoroutineContext().isActive || destroyed) {
                if (handle >= 0) {
                    try {
                        GoBackend.wgTurnOff(handle)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error turning off superseded tunnel", e)
                    }
                }
                activeHandle = -1
                if (TunnelManager.vpnHandle == handle) {
                    TunnelManager.vpnHandle = -1
                }
                TunnelManager.updateState(TunnelStatus.DISCONNECTED)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            if (handle < 0) {
                TunnelManager.updateState(TunnelStatus.ERROR, "Ошибка инициализации WireGuard (Код: $handle)")
                stopSelf()
                return
            }

            activeHandle = handle
            TunnelManager.vpnHandle = handle

            val activeStrategyDesc = if (profile.hasEmbeddedStrategy) {
                "В конфиге: ${profile.embeddedStrategy}"
            } else {
                strategy.name
            }

            TunnelManager.updateState(
                status = TunnelStatus.CONNECTED,
                profileName = profile.name,
                profileId = profile.id,
                mode = TunnelMode.VPN,
                strategyName = activeStrategyDesc
            )

            val repository = AppRepository(this@TravonetVpnService)
            if (repository.isWakeLockEnabled()) {
                acquireWakeLock()
            } else {
                releaseWakeLock()
            }

            if (repository.isForegroundServiceEnabled()) {
                startForegroundServiceNotification(profile.name, activeStrategyDesc, "Подключено")
            } else {
                stopForeground(STOP_FOREGROUND_REMOVE)
            }
            startStatsPolling(handle, profile.name, activeStrategyDesc)
            startHandshakeWatchdog(handle, profile, strategy, attempt)

        } catch (e: kotlinx.coroutines.CancellationException) {
            Log.i(TAG, "startTunnel was cancelled")
            releaseTunnelLocked()
            TunnelManager.vpnHandle = -1
            TunnelManager.updateState(TunnelStatus.DISCONNECTED)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        } catch (e: Throwable) {
            Log.e(TAG, "Fatal error in startTunnel", e)
            releaseTunnelLocked()
            TunnelManager.vpnHandle = -1
            TunnelManager.updateState(TunnelStatus.ERROR, e.localizedMessage ?: "Неизвестная ошибка")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun startStatsPolling(handle: Int, profileName: String, strategyDesc: String) {
        statsJob?.cancel()
        statsJob = serviceScope.launch {
            while (isActive && TunnelManager.vpnHandle == handle) {
                delay(2000)
                try {
                    val configDump = GoBackend.wgGetConfig(handle)
                    val stats = TunnelManager.parseUapiStats(configDump)
                    TunnelManager.updateStats(stats)

                    val repository = AppRepository(this@TravonetVpnService)
                    if (repository.isForegroundServiceEnabled()) {
                        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                        nm.notify(
                            NOTIFICATION_ID,
                            buildNotification(
                                profileName,
                                strategyDesc,
                                "↑ ${stats.formattedTx()}  ↓ ${stats.formattedRx()}"
                            )
                        )
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error fetching wgGetConfig", e)
                }
            }
        }
    }

    /**
     * Watches for the initial WireGuard handshake, or reconnects if connection is lost.
     */
    private fun startHandshakeWatchdog(
        handle: Int,
        profile: com.travonet.wireguard.model.WgProfile,
        strategy: com.travonet.wireguard.model.EvasionStrategy,
        attempt: Int = 0
    ) {
        healthJob?.cancel()
        healthJob = serviceScope.launch {
            val deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS
            var initialHandshakeReceived = false
            while (isActive && System.currentTimeMillis() < deadline) {
                delay(1000)
                if (TunnelManager.vpnHandle != handle) return@launch
                val configDump = try {
                    GoBackend.wgGetConfig(handle)
                } catch (e: Exception) {
                    null
                }
                if (TunnelManager.parseUapiStats(configDump).lastHandshakeSec > 0L) {
                    initialHandshakeReceived = true
                    break
                }
            }

            val repository = AppRepository(this@TravonetVpnService)
            if (!initialHandshakeReceived) {
                if (TunnelManager.vpnHandle == handle &&
                    (TunnelManager.state.value.status == TunnelStatus.CONNECTED ||
                     TunnelManager.state.value.status == TunnelStatus.CONNECTING)
                ) {
                    if (repository.isAutoReconnectEnabled() && attempt < 2) {
                        Log.w(TAG, "No WireGuard handshake (attempt ${attempt + 1}/3); auto-reconnecting...")
                        TunnelManager.updateState(TunnelStatus.CONNECTING, "Переподключение (попытка ${attempt + 2}/3)...")
                        tunnelMutex.withLock {
                            releaseTunnelLocked()
                        }
                        delay(2000)
                        if (isActive && !destroyed) {
                            tunnelMutex.withLock {
                                startTunnelLocked(profile, strategy, attempt + 1)
                            }
                        }
                        return@launch
                    } else {
                        Log.w(TAG, "No WireGuard handshake after attempts; tearing down")
                        tunnelMutex.withLock {
                            releaseTunnelLocked()
                        }
                        TunnelManager.vpnHandle = -1
                        TunnelManager.updateState(
                            TunnelStatus.ERROR,
                            "Сервер не ответил на handshake (${if (attempt >= 2) "3 попытки" else "${HANDSHAKE_TIMEOUT_MS / 1000} с"}). Смените стратегию или профиль."
                        )
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }
                }
            }

            if (!repository.isAutoReconnectEnabled()) return@launch

            // Auto-reconnect watchdog if connection drops after initial handshake
            var staleCount = 0
            while (isActive && TunnelManager.vpnHandle == handle) {
                delay(5000)
                val configDump = try {
                    GoBackend.wgGetConfig(handle)
                } catch (e: Exception) {
                    null
                }
                val stats = TunnelManager.parseUapiStats(configDump)
                val nowSec = System.currentTimeMillis() / 1000
                if (stats.lastHandshakeSec > 0L && (nowSec - stats.lastHandshakeSec) > 150) {
                    staleCount++
                    if (staleCount >= 4) {
                        Log.w(TAG, "Connection lost (handshake stale for ${nowSec - stats.lastHandshakeSec}s); auto-reconnecting...")
                        TunnelManager.updateState(TunnelStatus.CONNECTING, "Восстановление соединения...")
                        tunnelMutex.withLock {
                            releaseTunnelLocked()
                        }
                        delay(2000)
                        if (isActive && !destroyed) {
                            tunnelMutex.withLock {
                                startTunnelLocked(profile, strategy, 0)
                            }
                        }
                        return@launch
                    }
                } else {
                    staleCount = 0
                }
            }
        }
    }

    private fun stopTunnelAsync() {
        Log.i(TAG, "stopTunnelAsync requested")
        // 1. Immediately cancel active coroutines
        startJob?.cancel()
        healthJob?.cancel()
        statsJob?.cancel()
        healthJob = null
        statsJob = null

        // 2. Direct emergency kill if handle exists, without waiting for mutex lock
        val currentHandle = activeHandle
        val globalHandle = TunnelManager.vpnHandle
        val handleToKill = if (currentHandle >= 0) currentHandle else globalHandle
        if (handleToKill >= 0) {
            try {
                GoBackend.wgTurnOff(handleToKill)
            } catch (e: Exception) {
                Log.e(TAG, "Error in emergency wgTurnOff", e)
            }
        }
        activeHandle = -1
        TunnelManager.vpnHandle = -1

        try {
            activePfd?.close()
        } catch (e: Exception) {
            // ignore
        }
        activePfd = null

        TunnelManager.updateState(TunnelStatus.DISCONNECTED)
        stopForeground(STOP_FOREGROUND_REMOVE)

        // 3. Clean up the rest under mutex asynchronously and stop service
        serviceScope.launch {
            try {
                tunnelMutex.withLock {
                    releaseTunnelLocked()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error in releaseTunnelLocked during stop", e)
            } finally {
                TunnelManager.updateState(TunnelStatus.DISCONNECTED)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /**
     * Releases only the tunnel owned by this service instance. Idempotent and
     * safe to call from onDestroy after a stop already released it.
     *
     * @return the native handle that was released, or -1.
     */
    private fun releaseTunnelLocked(): Int {
        releaseWakeLock()
        unregisterNetworkCallback()
        healthJob?.cancel()
        healthJob = null
        statsJob?.cancel()
        statsJob = null

        val handle = activeHandle
        activeHandle = -1

        if (handle >= 0) {
            try {
                GoBackend.wgTurnOff(handle)
            } catch (e: Exception) {
                Log.e(TAG, "Error turning off tunnel", e)
            }

            if (TunnelManager.vpnHandle == handle) {
                TunnelManager.vpnHandle = -1

                // Нативный слой держит NewGlobalRef на VpnService; без этого
                // вызова объект сервиса остаётся живым до смерти процесса.
                // Не трогаем глобальную ссылку, если новый экземпляр сервиса
                // уже зарегистрировал свой VpnService.
                try {
                    GoBackend.wgSetVpnService(null)
                } catch (e: Exception) {
                    Log.e(TAG, "Error releasing VpnService reference", e)
                }
            }
        }

        try {
            activePfd?.close()
        } catch (e: Exception) {
            // ignore: the descriptor may already be detached/closed by the core
        }
        activePfd = null
        return handle
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked by the system")
        // wgTurnOff ждёт завершения горутин устройства — уводим это с main thread.
        serviceScope.launch {
            tunnelMutex.withLock {
                releaseTunnelLocked()
            }
            if (TunnelManager.vpnHandle == -1) {
                TunnelManager.updateState(TunnelStatus.ERROR, "VPN отключён системой")
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onDestroy() {
        destroyed = true
        startJob?.cancel()
        releaseTunnelLocked()
        super.onDestroy()
    }

    private fun registerNetworkCallback() {
        if (defaultNetworkCallback != null) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        connectivityManager = cm
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setUnderlyingNetworks(arrayOf(network))
                }
            }

            override fun onLost(network: Network) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setUnderlyingNetworks(null)
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setUnderlyingNetworks(arrayOf(network))
                }
            }
        }
        try {
            cm.registerDefaultNetworkCallback(callback)
            defaultNetworkCallback = callback
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register default network callback", e)
        }
    }

    private fun unregisterNetworkCallback() {
        defaultNetworkCallback?.let {
            try {
                connectivityManager?.unregisterNetworkCallback(it)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to unregister network callback", e)
            }
            defaultNetworkCallback = null
        }
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        try {
            val powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager
            wakeLock = powerManager?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TravonetWG::VpnWakeLock")?.apply {
                setReferenceCounted(false)
                acquire(12 * 60 * 60 * 1000L) // 12 hours max safety timeout
            }
            Log.d(TAG, "WakeLock acquired")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to acquire wake lock", e)
        }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
                Log.d(TAG, "WakeLock released")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to release wake lock", e)
        } finally {
            wakeLock = null
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "TravonetWG VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Статус подключения VPN-туннеля TravonetWG"
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun startForegroundServiceNotification(profileName: String, strategyDesc: String, subtext: String) {
        val notification = buildNotification(profileName, strategyDesc, subtext)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, 0)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(profileName: String, strategyDesc: String, subtext: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, TravonetVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("TravonetWG: $profileName")
            .setContentText("Обход DPI: $strategyDesc")
            .setSubText(subtext)
            .setOngoing(true)
            .setContentIntent(openPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отключить", stopPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
