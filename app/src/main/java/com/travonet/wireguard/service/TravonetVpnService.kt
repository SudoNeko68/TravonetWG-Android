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
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import com.travonet.wireguard.MainActivity
import com.travonet.wireguard.R
import com.travonet.wireguard.model.DnsMode
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
    private var activeTunFd: Int = -1
    @Volatile private var destroyed = false
    @Volatile private var isProxyActive = false
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null
    @Volatile private var physicalNetwork: Network? = null
    private val repository by lazy { AppRepository(this) }

    companion object {
        const val TAG = "TravonetVPN"
        const val ACTION_START = "com.travonet.wireguard.action.START_VPN"
        const val ACTION_STOP = "com.travonet.wireguard.action.STOP_VPN"
        const val EXTRA_PROFILE_ID = "profile_id"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "travonet_vpn_channel"
        private const val HANDSHAKE_TIMEOUT_MS = 45_000L
    }

    private var serviceReceiver: android.content.BroadcastReceiver? = null

    override fun onCreate() {
        super.onCreate()
        TunnelManager.init(this)
        serviceReceiver = TunnelManager.registerServiceReceiver(this)
        createNotificationChannel()
        com.freevpn.coreloader.NativeCoreBridge.setCoreEventListener(object : com.freevpn.coreloader.CoreEventListener {
            override fun onCoreEvent(eventType: Int, payload: String) {
                when (eventType) {
                    1 -> {
                        val url = if (payload.isNotBlank()) payload else "http://127.0.0.1:8765"
                        TunnelManager.showCaptcha(url)
                    }
                    2 -> {
                        TunnelManager.hideCaptcha()
                    }
                }
            }
        })
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_STOP) {
            stopTunnelAsync()
            return START_NOT_STICKY
        }

        if (action == ACTION_START) {
            val profileId = intent.getStringExtra(EXTRA_PROFILE_ID)
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
            return START_REDELIVER_INTENT
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

            val routing = com.travonet.wireguard.core.CoreRouter.route(
                profile.rawConfig,
                AppRepository(this@TravonetVpnService).getProtocolDelegations()
            )
            if (routing.targetCore == com.travonet.wireguard.core.CoreType.FREETURN) {
                startFreeTurnTunnelLocked(profile, routing, strategy, attempt)
                return
            } else if (routing.targetCore != com.travonet.wireguard.core.CoreType.TRAVONET_WG) {
                startProxyTunnelLocked(profile, routing)
                return
            }

            val parsed = WgConfigParser.parse(profile.rawConfig)
            val preparedConfig = WgConfigParser.prepareConfigForLaunch(profile, strategy)
            val keepaliveConfig = WgConfigParser.ensurePersistentKeepalive(preparedConfig)
            val resolvedConfig = WgConfigParser.resolveConfigEndpoints(keepaliveConfig)

            val builder = Builder()
                .setSession("TravonetVPN - ${profile.name}")
                .setMtu(parsed.iface.mtu)
                .setBlocking(false)

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

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.allowFamily(OsConstants.AF_INET)
                if (hasIpv6) {
                    builder.allowFamily(OsConstants.AF_INET6)
                }
            }

            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to exclude package from TUN", e)
            }

            builder.allowBypass()

            // Add DNS
            var dnsCount = 0
            val dnsMode = repository.getDnsMode()
            val effectiveDns: List<String> = repository.getEffectiveDnsServers()
            val profileDns = parsed.iface.dnsServers.filter { !isPrivateIp(it.trim()) }
            val dnsServers = when (dnsMode) {
                DnsMode.SYSTEM -> {
                    val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                    val lp = physicalNetwork?.let { cm?.getLinkProperties(it) } ?: cm?.getLinkProperties(cm?.activeNetwork)
                    val sysList = lp?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()
                    val publicSysList = sysList.filter { !isPrivateIp(it.trim()) }
                    publicSysList.ifEmpty { profileDns.ifEmpty { listOf("77.88.8.8", "8.8.8.8", "1.1.1.1") } }
                }
                DnsMode.SERVER -> profileDns.ifEmpty { listOf("1.1.1.1", "8.8.8.8") }
                DnsMode.CUSTOM -> {
                    val custom = effectiveDns.filter { !isPrivateIp(it.trim()) }
                    custom.ifEmpty { profileDns.ifEmpty { listOf("1.1.1.1", "8.8.8.8") } }
                }
            }

            dnsServers.forEach { dnsStr: String ->
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

            val currentPfd = builder.establish()
            if (currentPfd == null) {
                TunnelManager.updateState(TunnelStatus.ERROR, "Не удалось создать системный TUN интерфейс")
                stopSelf()
                return
            }
            activePfd = currentPfd
            val tunFd = currentPfd.detachFd()

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

            // Always maintain foreground service status while tunnel is connected
            startForegroundServiceNotification(profile.name, activeStrategyDesc, "Подключено")
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
            var prevTxBytes = -1L
            var prevRxBytes = -1L
            while (isActive && TunnelManager.vpnHandle == handle) {
                delay(5000)
                val configDump = try {
                    GoBackend.wgGetConfig(handle)
                } catch (e: Exception) {
                    null
                }
                val stats = TunnelManager.parseUapiStats(configDump)
                val nowSec = System.currentTimeMillis() / 1000

                // Соединение считается потерянным ТОЛЬКО если:
                // 1. Был первоначальный handshake (lastHandshakeSec > 0).
                // 2. Идет отправка пакетов (txBytes растет), но нет ответа (rxBytes не меняется).
                // 3. Handshake не обновлялся более 180 секунд (Reject-After-Time в WireGuard).
                // Если телефон в режиме ожидания (нет отправки пакетов), WireGuard намеренно
                // не производит handshake (тишина в эфире) — туннель не должен разрываться.
                val hasOutgoingTraffic = prevTxBytes >= 0L && (stats.txBytes - prevTxBytes) > 500L
                val noIncomingTraffic = prevRxBytes >= 0L && stats.rxBytes == prevRxBytes
                val isHandshakeStale = stats.lastHandshakeSec > 0L && (nowSec - stats.lastHandshakeSec) > 180

                if (hasOutgoingTraffic && noIncomingTraffic && isHandshakeStale) {
                    staleCount++
                    if (staleCount >= 3) { // 15 секунд подтвержденного отсутствия ответа при отправке
                        Log.w(TAG, "Connection lost (outgoing traffic without response for ${nowSec - stats.lastHandshakeSec}s); auto-reconnecting...")
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

                prevTxBytes = stats.txBytes
                prevRxBytes = stats.rxBytes
            }
        }
    }

    private suspend fun startFreeTurnTunnelLocked(
        profile: com.travonet.wireguard.model.WgProfile,
        routing: com.travonet.wireguard.core.RoutingResult,
        strategy: com.travonet.wireguard.model.EvasionStrategy,
        attempt: Int = 0
    ) {
        val targetCore = routing.targetCore
        if (!com.travonet.wireguard.core.CoreManager.isInstalled(this@TravonetVpnService, targetCore)) {
            TunnelManager.updateState(
                TunnelStatus.ERROR,
                "Не установлено ядро ${targetCore.title}. Проверьте его во вкладке «Ядра»."
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val corePath = com.travonet.wireguard.core.CoreManager.getCoreFilePath(this@TravonetVpnService, targetCore)
        if (corePath == null) {
            TunnelManager.updateState(
                TunnelStatus.ERROR,
                "Файл ядра ${targetCore.title} не найден."
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val configStr = try {
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(profile.rawConfig, targetCore)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to synthesize FreeTURN config", e)
            TunnelManager.updateState(
                TunnelStatus.ERROR,
                "Ошибка формирования конфигурации FreeTURN: ${e.localizedMessage ?: "Синтаксическая ошибка"}"
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val wgConfigRaw = com.travonet.wireguard.parser.ProxyLinkParser.extractEmbeddedWgConfig(profile.rawConfig)
        val needsTun = com.freevpn.coreloader.NativeCoreBridge.checkNeedsTunNative(corePath, configStr) || (wgConfigRaw != null)

        var tunFd = -1
        if (needsTun) {
            val wgConfigToParse = wgConfigRaw ?: profile.rawConfig
            val parsed = try {
                WgConfigParser.parse(wgConfigToParse)
            } catch (e: Exception) {
                null
            }

            val mtu = if (parsed != null && parsed.iface.mtu in 1120..1420) parsed.iface.mtu else 1280
            val builder = Builder()
                .setSession("TravonetVPN - ${profile.name} (FreeTURN)")
                .setMtu(mtu)
                .setBlocking(false)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            var hasIpv4 = false
            var hasIpv6 = false
            parsed?.iface?.addresses?.forEach { addrStr ->
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
                builder.addAddress("10.13.13.3", 32)
            }

            var routeCount = 0
            parsed?.peers?.forEach { peer ->
                peer.allowedIps.forEach { routeStr ->
                    try {
                        val parts = routeStr.split("/")
                        val ip = parts[0].trim()
                        val isV6 = ip.contains(":")
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
                        Log.w(TAG, "Failed to parse allowed ip: $routeStr", e)
                    }
                }
            }
            if (routeCount == 0) {
                if (hasIpv4) builder.addRoute("0.0.0.0", 0)
                if (hasIpv6) builder.addRoute("::", 0)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.allowFamily(android.system.OsConstants.AF_INET)
                if (hasIpv6) {
                    builder.allowFamily(android.system.OsConstants.AF_INET6)
                }
            }

            val proxyDnsMode = repository.getDnsMode()
            val proxyEffectiveDns = repository.getEffectiveDnsServers()
            val proxyProfileDns = (parsed?.iface?.dnsServers ?: emptyList()).filter { !isPrivateIp(it.trim()) }
            val proxyDnsServers = when (proxyDnsMode) {
                DnsMode.SYSTEM -> {
                    val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                    val lp = physicalNetwork?.let { cm?.getLinkProperties(it) } ?: cm?.getLinkProperties(cm?.activeNetwork)
                    val sysList = lp?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()
                    val publicSysList = sysList.filter { !isPrivateIp(it.trim()) }
                    publicSysList.ifEmpty { proxyProfileDns.ifEmpty { listOf("77.88.8.8", "8.8.8.8", "1.1.1.1") } }
                }
                DnsMode.SERVER -> proxyProfileDns.ifEmpty { listOf("1.1.1.1", "8.8.8.8") }
                DnsMode.CUSTOM -> {
                    val custom = proxyEffectiveDns.filter { !isPrivateIp(it.trim()) }
                    custom.ifEmpty { proxyProfileDns.ifEmpty { listOf("1.1.1.1", "8.8.8.8") } }
                }
            }

            proxyDnsServers.forEach { dnsStr ->
                try {
                    val dns = dnsStr.trim()
                    val isV6 = dns.contains(":")
                    if (isV6 && !hasIpv6) {
                        return@forEach
                    }
                    builder.addDnsServer(dns)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to parse DNS: $dnsStr", e)
                }
            }

            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to exclude package from TUN", e)
            }

            builder.allowBypass()

            val currentPfd = builder.establish()
            if (currentPfd == null) {
                TunnelManager.updateState(TunnelStatus.ERROR, "Не удалось создать системный TUN интерфейс для FreeTURN")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }
            activePfd = currentPfd
            tunFd = currentPfd.detachFd()
            activeTunFd = tunFd
            registerNetworkCallback()
        }

        var lastErr = ""
        val started = runCatching {
            var ok = false
            val t = kotlin.concurrent.thread(name = "FreeTurn-Init", start = true) {
                ok = com.freevpn.coreloader.NativeCoreBridge.startProxyWithCore(corePath, configStr, tunFd)
                if (!ok) {
                    lastErr = com.freevpn.coreloader.NativeCoreBridge.getLastCoreErrorNative()
                }
            }
            t.join()
            ok
        }.getOrDefault(false)

        if (!started) {
            val err = lastErr
            Log.e(TAG, "FreeTURN core failed to start: $err")
            if (activeTunFd >= 0) {
                try {
                    ParcelFileDescriptor.adoptFd(activeTunFd).close()
                } catch (_: Exception) {}
                activeTunFd = -1
            }
            activePfd = null
            val displayErr = if (err.isNotBlank()) err else "Не удалось запустить ядро FreeTURN"
            TunnelManager.updateState(TunnelStatus.ERROR, displayErr)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        isProxyActive = true
        activeHandle = 99998
        TunnelManager.vpnHandle = 99998
        val activeDesc = if (needsTun) "FreeTURN (VK Relay) + WireGuard" else "FreeTURN Релей (127.0.0.1:9000)"
        TunnelManager.updateState(
            status = TunnelStatus.CONNECTED,
            profileName = profile.name,
            profileId = profile.id,
            mode = TunnelMode.VPN,
            strategyName = activeDesc
        )

        val repository = AppRepository(this@TravonetVpnService)
        if (repository.isWakeLockEnabled()) acquireWakeLock() else releaseWakeLock()
        startForegroundServiceNotification(profile.name, activeDesc, "Подключено")
        startProxyWatchdog(profile.name, "FreeTURN")
    }

    private fun startProxyTunnelLocked(
        profile: com.travonet.wireguard.model.WgProfile,
        routing: com.travonet.wireguard.core.RoutingResult
    ) {
        val targetCore = routing.targetCore
        if (!com.travonet.wireguard.core.CoreManager.isInstalled(this@TravonetVpnService, targetCore)) {
            TunnelManager.updateState(
                TunnelStatus.ERROR,
                "Не установлено ядро ${targetCore.title} для ${routing.detectedProtocol}. Установите его во вкладке «Ядра»."
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val corePath = com.travonet.wireguard.core.CoreManager.getCoreFilePath(this@TravonetVpnService, targetCore)
        if (corePath == null) {
            TunnelManager.updateState(
                TunnelStatus.ERROR,
                "Файл ядра ${targetCore.title} не найден."
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val dohUrl = repository.getEffectiveDnsDohUrl()
        val dnsMode = repository.getDnsMode()
        val customHosts = repository.getCustomHosts()
        val configJson = try {
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
                profile.rawConfig,
                targetCore,
                mode = com.travonet.wireguard.model.TunnelMode.VPN,
                dohUrl = dohUrl,
                dnsMode = dnsMode,
                customHosts = customHosts
            ).also { Log.d(TAG, "Synthesized proxy config:\n$it") }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to synthesize proxy config", e)
            TunnelManager.updateState(
                TunnelStatus.ERROR,
                "Ошибка формирования конфигурации: ${e.localizedMessage ?: "Синтаксическая ошибка"}"
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val builder = Builder()
            .setSession("TravonetVPN - ${profile.name}")
            .setMtu(1420)
            .setBlocking(false)
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)

        builder.allowBypass()

        val effectiveDns: List<String> = repository.getEffectiveDnsServers()
        val builderDns = when (dnsMode) {
            DnsMode.SYSTEM -> {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                val lp = physicalNetwork?.let { cm?.getLinkProperties(it) } ?: cm?.getLinkProperties(cm?.activeNetwork)
                val sysList = lp?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()
                val filtered = sysList.filter { !it.contains(":") && !isPrivateIp(it.trim()) }
                if (filtered.isNotEmpty()) listOf("172.19.0.2") + filtered else listOf("172.19.0.2", "77.88.8.8", "1.1.1.1")
            }
            DnsMode.SERVER -> listOf("172.19.0.2", "1.1.1.1", "8.8.8.8")
            DnsMode.CUSTOM -> {
                val custom = effectiveDns.filter { !it.contains(":") && !isPrivateIp(it.trim()) }
                if (custom.isNotEmpty()) listOf("172.19.0.2") + custom else listOf("172.19.0.2", "1.1.1.1")
            }
        }
        builderDns.forEach { dns: String -> try { builder.addDnsServer(dns) } catch (_: Exception) {} }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.allowFamily(android.system.OsConstants.AF_INET)
            builder.setMetered(false)
        }

        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to exclude package from TUN", e)
        }

        val currentPfd = builder.establish()
        if (currentPfd == null) {
            TunnelManager.updateState(TunnelStatus.ERROR, "Не удалось создать системный TUN интерфейс")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        activePfd = currentPfd
        val tunFd = currentPfd.detachFd()
        activeTunFd = tunFd

        registerNetworkCallback()

        val started = com.freevpn.coreloader.NativeCoreBridge.startProxyWithCore(corePath, configJson, tunFd)
        if (!started) {
            val err = com.freevpn.coreloader.NativeCoreBridge.getLastCoreErrorNative()
            Log.e(TAG, "Proxy core failed to start: $err")
            if (activeTunFd >= 0) {
                try {
                    ParcelFileDescriptor.adoptFd(activeTunFd).close()
                } catch (_: Exception) {}
                activeTunFd = -1
            }
            activePfd = null
            val displayErr = if (err.isNotBlank()) err else "Не удалось запустить ядро ${targetCore.title}"
            TunnelManager.updateState(TunnelStatus.ERROR, displayErr)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        isProxyActive = true
        activeHandle = 99999
        TunnelManager.vpnHandle = 99999

        val coreTitle = targetCore.title
        val activeDesc = "Ядро: $coreTitle"
        TunnelManager.updateState(
            status = TunnelStatus.CONNECTED,
            profileName = profile.name,
            profileId = profile.id,
            mode = TunnelMode.VPN,
            strategyName = activeDesc
        )

        val repository = AppRepository(this@TravonetVpnService)
        if (repository.isWakeLockEnabled()) {
            acquireWakeLock()
        } else {
            releaseWakeLock()
        }

        // Always maintain foreground service status while proxy core is active
        startForegroundServiceNotification(profile.name, activeDesc, "Подключено")

        startProxyWatchdog(profile.name, coreTitle)
    }

    private fun startProxyWatchdog(profileName: String, coreTitle: String) {
        statsJob?.cancel()
        healthJob?.cancel()
        statsJob = serviceScope.launch {
            val repository = AppRepository(this@TravonetVpnService)
            val myUid = android.os.Process.myUid()
            val startTx = android.net.TrafficStats.getUidTxBytes(myUid).let { if (it < 0) 0L else it }
            val startRx = android.net.TrafficStats.getUidRxBytes(myUid).let { if (it < 0) 0L else it }

            while (isActive && isProxyActive) {
                delay(1500)
                if (!com.freevpn.coreloader.NativeCoreBridge.isProxyRunningNative()) {
                    val err = com.freevpn.coreloader.NativeCoreBridge.getLastCoreErrorNative()
                    Log.w(TAG, "Proxy core stopped unexpectedly: $err")
                    TunnelManager.updateState(
                        TunnelStatus.ERROR,
                        if (err.isNotBlank()) err else "Ядро $coreTitle аварийно завершило работу"
                    )
                    stopTunnelAsync()
                    break
                }

                val curTx = android.net.TrafficStats.getUidTxBytes(myUid)
                val curRx = android.net.TrafficStats.getUidRxBytes(myUid)
                val tx = if (curTx >= startTx) curTx - startTx else 0L
                val rx = if (curRx >= startRx) curRx - startRx else 0L
                val stats = com.travonet.wireguard.model.TunnelStats(txBytes = tx, rxBytes = rx)
                TunnelManager.updateStats(stats)

                if (repository.isForegroundServiceEnabled()) {
                    val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                    nm.notify(
                        NOTIFICATION_ID,
                        buildNotification(
                            profileName,
                            "Ядро: $coreTitle",
                            "↑ ${stats.formattedTx()}  ↓ ${stats.formattedRx()}"
                        )
                    )
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
        if (handleToKill in 0 until 90000) {
            try {
                GoBackend.wgTurnOff(handleToKill)
            } catch (e: Exception) {
                Log.e(TAG, "Error in emergency wgTurnOff", e)
            }
        }
        if (isProxyActive || com.freevpn.coreloader.NativeCoreBridge.isProxyRunningNative()) {
            try {
                com.freevpn.coreloader.NativeCoreBridge.stopCoreNative()
            } catch (e: Exception) {
                Log.e(TAG, "Error in emergency stopCoreNative", e)
            }
            isProxyActive = false
        }
        activeHandle = -1
        TunnelManager.vpnHandle = -1

        if (activeTunFd >= 0) {
            try {
                ParcelFileDescriptor.adoptFd(activeTunFd).close()
            } catch (_: Exception) {}
            activeTunFd = -1
        }
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

        if (handle in 0 until 90000) {
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

        if (isProxyActive || com.freevpn.coreloader.NativeCoreBridge.isProxyRunningNative()) {
            try {
                com.freevpn.coreloader.NativeCoreBridge.stopCoreNative()
            } catch (e: Exception) {
                Log.e(TAG, "Error in stopCoreNative during release", e)
            }
            isProxyActive = false
        }
        if (TunnelManager.vpnHandle >= 90000) {
            TunnelManager.vpnHandle = -1
        }

        if (activeTunFd >= 0) {
            try {
                ParcelFileDescriptor.adoptFd(activeTunFd).close()
            } catch (e: Exception) {
                Log.w(TAG, "Error closing activeTunFd in releaseTunnelLocked", e)
            }
            activeTunFd = -1
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

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.d(TAG, "onTaskRemoved: app task removed from recents, keeping VPN active")
    }

    override fun onDestroy() {
        destroyed = true
        startJob?.cancel()
        releaseTunnelLocked()
        serviceReceiver?.let {
            try {
                unregisterReceiver(it)
            } catch (_: Exception) {}
        }
        serviceReceiver = null
        super.onDestroy()
    }

    private fun registerNetworkCallback() {
        if (defaultNetworkCallback != null) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        connectivityManager = cm
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "Physical network available: $network")
                physicalNetwork = network
                updateUnderlyingNetwork()
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Physical network lost: $network")
                if (physicalNetwork == network) {
                    physicalNetwork = null
                }
                updateUnderlyingNetwork()
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                // Ignore transient RSSI / bandwidth capability changes to avoid flapping
            }
        }
        try {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(request, callback)
            defaultNetworkCallback = callback
            updateUnderlyingNetwork()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback", e)
            try { setUnderlyingNetworks(null) } catch (_: Exception) {}
        }
    }

    private fun updateUnderlyingNetwork() {
        try {
            val net = physicalNetwork
            if (net != null) {
                Log.d(TAG, "Setting active physical underlying network: $net")
                setUnderlyingNetworks(arrayOf(net))
                return
            }
            Log.d(TAG, "Resetting underlying network to auto (null)")
            setUnderlyingNetworks(null)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update underlying networks", e)
            try { setUnderlyingNetworks(null) } catch (_: Exception) {}
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
        physicalNetwork = null
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld != true) {
            try {
                val powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager
                wakeLock = powerManager?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TravonetVPN::VpnWakeLock")?.apply {
                    setReferenceCounted(false)
                    acquire(12 * 60 * 60 * 1000L) // 12 hours max safety timeout
                }
                Log.d(TAG, "WakeLock acquired")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to acquire wake lock", e)
            }
        }
        if (wifiLock?.isHeld != true) {
            try {
                val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as? android.net.wifi.WifiManager
                val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    android.net.wifi.WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                } else {
                    android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF
                }
                wifiLock = wifiManager?.createWifiLock(mode, "TravonetVPN::VpnWifiLock")?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
                Log.d(TAG, "WifiLock acquired")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to acquire wifi lock", e)
            }
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
        try {
            if (wifiLock?.isHeld == true) {
                wifiLock?.release()
                Log.d(TAG, "WifiLock released")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to release wifi lock", e)
        } finally {
            wifiLock = null
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "TravonetVPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Статус подключения VPN-туннеля TravonetVPN"
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun startForegroundServiceNotification(profileName: String, strategyDesc: String, subtext: String) {
        val notification = buildNotification(profileName, strategyDesc, subtext)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
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
            .setContentTitle("TravonetVPN: $profileName")
            .setContentText("Обход DPI: $strategyDesc")
            .setSubText(subtext)
            .setOngoing(true)
            .setContentIntent(openPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отключить", stopPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun isPrivateIp(ip: String): Boolean {
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") || ip.startsWith("169.254.")) return true
        if (ip.startsWith("172.")) {
            val second = ip.split(".").getOrNull(1)?.toIntOrNull() ?: 0
            if (second in 16..31) return true
        }
        return false
    }
}
