package com.travonet.wireguard.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import com.freevpn.coreloader.NativeCoreBridge
import com.travonet.wireguard.MainActivity
import com.travonet.wireguard.R
import com.travonet.wireguard.core.CoreManager
import com.travonet.wireguard.core.CoreRouter
import com.travonet.wireguard.core.CoreType
import com.travonet.wireguard.model.DnsMode
import com.travonet.wireguard.model.TunnelMode
import com.travonet.wireguard.model.TunnelStatus
import com.travonet.wireguard.parser.ProxyConfigSynthesizer
import com.travonet.wireguard.parser.WgConfigParser
import com.travonet.wireguard.repository.AppRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.travonet.backend.GoBackend

class TravonetSocksService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO)
    private var startJob: Job? = null
    private var statsJob: Job? = null
    private var isProxyActive = false
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: android.net.wifi.WifiManager.WifiLock? = null
    private val repository by lazy { AppRepository(this) }

    companion object {
        const val TAG = "TravonetSocks"
        const val ACTION_START = "com.travonet.wireguard.action.START_SOCKS"
        const val ACTION_STOP = "com.travonet.wireguard.action.STOP_SOCKS"
        const val EXTRA_PROFILE_ID = "profile_id"
        private const val NOTIFICATION_ID = 1002
        private const val CHANNEL_ID = "travonet_socks_channel"
        private const val PROXY_SOCKS_HANDLE = 99997
    }

    private var serviceReceiver: android.content.BroadcastReceiver? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        TunnelManager.init(this)
        serviceReceiver = TunnelManager.registerServiceReceiver(this)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_STOP) {
            stopProxy()
            return START_NOT_STICKY
        }

        if (action == ACTION_START) {
            val profileId = intent.getStringExtra(EXTRA_PROFILE_ID)
            Log.i(TAG, "onStartCommand: ACTION_START with profileId=$profileId")
            val profile = repository.getProfiles().firstOrNull { it.id == profileId }
                ?: repository.getSelectedProfile()

            if (profile == null) {
                Log.e(TAG, "Profile not found for id: $profileId")
                TunnelManager.updateState(TunnelStatus.ERROR, "Профиль не найден")
                stopSelf()
                return START_NOT_STICKY
            }

            val listenAddr = repository.getSocksListenAddr()
            Log.i(TAG, "Selected profile: ${profile.name} (id=${profile.id}), listen=$listenAddr")
            // Immediately start foreground notification to satisfy Android Foreground Service watchdog
            startForegroundServiceNotification(profile.name, listenAddr, "Запуск SOCKS5...")

            val strategy = repository.getSelectedStrategy()
            startProxy(profile, strategy, listenAddr)
            return START_REDELIVER_INTENT
        }

        return START_NOT_STICKY
    }

    private fun startProxy(
        profile: com.travonet.wireguard.model.WgProfile,
        strategy: com.travonet.wireguard.model.EvasionStrategy,
        listenAddr: String
    ) {
        startJob?.cancel()
        startJob = serviceScope.launch {
            try {
                // Clean up previous tunnel if any
                if (TunnelManager.socksHandle in 0 until 90000) {
                    try {
                        GoBackend.wgStopSocks5(TunnelManager.socksHandle)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error stopping previous wg socks", e)
                    }
                }
                if (isProxyActive || NativeCoreBridge.isProxyRunningNative()) {
                    try {
                        NativeCoreBridge.stopCoreNative()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error stopping previous proxy core", e)
                    }
                    isProxyActive = false
                }
                TunnelManager.socksHandle = -1

                val delegations = AppRepository(this@TravonetSocksService).getProtocolDelegations()
                val routing = CoreRouter.route(profile.rawConfig, delegations)
                Log.i(TAG, "startProxy: profile=${profile.name}, targetCore=${routing.targetCore}, proto=${routing.detectedProtocol}, rawConfigPrefix=${profile.rawConfig.take(30)}")

                if (routing.targetCore == CoreType.TRAVONET_WG) {
                    Log.i(TAG, "Launching via TravonetWG GoBackend")
                    val preparedConfig = WgConfigParser.prepareConfigForLaunch(profile, strategy)
                    val keepaliveConfig = WgConfigParser.ensurePersistentKeepalive(preparedConfig)
                    val handle = GoBackend.wgStartSocks5(listenAddr, keepaliveConfig)
                    if (handle < 0) {
                        TunnelManager.updateState(TunnelStatus.ERROR, "Ошибка запуска SOCKS5 прокси (Код: $handle)")
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }

                    TunnelManager.socksHandle = handle

                    val activeStrategyDesc = if (profile.hasEmbeddedStrategy) {
                        "В конфиге: ${profile.embeddedStrategy}"
                    } else {
                        strategy.name
                    }

                    TunnelManager.updateState(
                        status = TunnelStatus.CONNECTED,
                        profileName = profile.name,
                        profileId = profile.id,
                        mode = TunnelMode.SOCKS5,
                        strategyName = activeStrategyDesc
                    )

                    if (repository.isWakeLockEnabled()) {
                        acquireWakeLock()
                    } else {
                        releaseWakeLock()
                    }

                    startForegroundServiceNotification(profile.name, listenAddr, "Прокси активен на $listenAddr")
                    startStatsPolling(handle, profile.name, listenAddr)
                } else {
                    // Proxy cores: Xray, Sing-Box, FreeTURN
                    val targetCore = routing.targetCore
                    if (!CoreManager.isInstalled(this@TravonetSocksService, targetCore)) {
                        TunnelManager.updateState(
                            TunnelStatus.ERROR,
                            "Не установлено ядро ${targetCore.title} для ${routing.detectedProtocol}. Установите его во вкладке «Ядра»."
                        )
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }

                    val corePath = CoreManager.getCoreFilePath(this@TravonetSocksService, targetCore)
                    if (corePath == null) {
                        TunnelManager.updateState(
                            TunnelStatus.ERROR,
                            "Файл ядра ${targetCore.title} не найден."
                        )
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }

                    val dohUrl = repository.getEffectiveDnsDohUrl()
                    val dnsMode = repository.getDnsMode()
                    val customHosts = repository.getCustomHosts()
                    val configJson = try {
                        ProxyConfigSynthesizer.synthesize(
                            profile.rawConfig,
                            targetCore,
                            mode = TunnelMode.SOCKS5,
                            socksListen = listenAddr,
                            dohUrl = dohUrl,
                            dnsMode = dnsMode,
                            customHosts = customHosts
                        )
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to synthesize proxy config for SOCKS5", e)
                        TunnelManager.updateState(
                            TunnelStatus.ERROR,
                            "Ошибка формирования конфигурации: ${e.localizedMessage ?: "Синтаксическая ошибка"}"
                        )
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }

                    var lastErr = ""
                    val started = runCatching {
                        var ok = false
                        val t = kotlin.concurrent.thread(name = "SocksProxy-Init", start = true) {
                            // tunFd = -1 signals SOCKS mode without TUN interface
                            ok = NativeCoreBridge.startProxyWithCore(corePath, configJson, -1)
                            if (!ok) {
                                lastErr = NativeCoreBridge.getLastCoreErrorNative()
                            }
                        }
                        t.join()
                        ok
                    }.getOrDefault(false)

                    if (!started) {
                        val displayErr = if (lastErr.isNotBlank()) lastErr else "Не удалось запустить ядро ${targetCore.title}"
                        Log.e(TAG, "Proxy core failed to start in SOCKS mode: $displayErr")
                        TunnelManager.updateState(TunnelStatus.ERROR, displayErr)
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }

                    isProxyActive = true
                    TunnelManager.socksHandle = PROXY_SOCKS_HANDLE

                    val activeStrategyDesc = if (profile.hasEmbeddedStrategy) {
                        "В конфиге: ${profile.embeddedStrategy}"
                    } else {
                        "${targetCore.title} (${routing.detectedProtocol})"
                    }

                    TunnelManager.updateState(
                        status = TunnelStatus.CONNECTED,
                        profileName = profile.name,
                        profileId = profile.id,
                        mode = TunnelMode.SOCKS5,
                        strategyName = activeStrategyDesc
                    )

                    if (repository.isWakeLockEnabled()) {
                        acquireWakeLock()
                    } else {
                        releaseWakeLock()
                    }

                    startForegroundServiceNotification(
                        profile.name,
                        listenAddr,
                        "SOCKS5 активен на $listenAddr (${targetCore.title})"
                    )
                    startProxyWatchdog(PROXY_SOCKS_HANDLE, profile.name, listenAddr, targetCore.title)
                }

            } catch (e: kotlinx.coroutines.CancellationException) {
                Log.i(TAG, "startProxy was cancelled")
                releaseWakeLock()
                TunnelManager.socksHandle = -1
                isProxyActive = false
                TunnelManager.updateState(TunnelStatus.DISCONNECTED)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            } catch (e: Throwable) {
                Log.e(TAG, "Error starting socks proxy", e)
                releaseWakeLock()
                TunnelManager.socksHandle = -1
                isProxyActive = false
                TunnelManager.updateState(TunnelStatus.ERROR, e.localizedMessage ?: "Неизвестная ошибка")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun startStatsPolling(handle: Int, profileName: String, listenAddr: String) {
        statsJob?.cancel()
        statsJob = serviceScope.launch {
            while (isActive && TunnelManager.socksHandle == handle) {
                delay(2000)
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.notify(
                    NOTIFICATION_ID,
                    buildNotification(
                        profileName,
                        listenAddr,
                        "SOCKS5 порт: $listenAddr (Активен)"
                    )
                )
            }
        }
    }

    private fun startProxyWatchdog(
        handle: Int,
        profileName: String,
        listenAddr: String,
        coreTitle: String
    ) {
        statsJob?.cancel()
        statsJob = serviceScope.launch {
            while (isActive && TunnelManager.socksHandle == handle) {
                delay(2000)
                if (!NativeCoreBridge.isProxyRunningNative()) {
                    Log.e(TAG, "Proxy core $coreTitle unexpectedly stopped in SOCKS mode")
                    releaseWakeLock()
                    TunnelManager.socksHandle = -1
                    isProxyActive = false
                    TunnelManager.updateState(TunnelStatus.ERROR, "Ядро $coreTitle аварийно завершило работу")
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    break
                }
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.notify(
                    NOTIFICATION_ID,
                    buildNotification(
                        profileName,
                        listenAddr,
                        "SOCKS5 ($coreTitle): $listenAddr"
                    )
                )
            }
        }
    }

    private fun stopProxy() {
        releaseWakeLock()
        startJob?.cancel()
        startJob = null
        statsJob?.cancel()
        statsJob = null

        val handle = TunnelManager.socksHandle
        if (handle in 0 until 90000) {
            try {
                GoBackend.wgStopSocks5(handle)
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping socks", e)
            }
        }
        TunnelManager.socksHandle = -1

        if (isProxyActive || NativeCoreBridge.isProxyRunningNative()) {
            try {
                NativeCoreBridge.stopCoreNative()
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping core in SOCKS mode", e)
            }
            isProxyActive = false
        }

        TunnelManager.updateState(TunnelStatus.DISCONNECTED)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.d(TAG, "onTaskRemoved: app task removed from recents, keeping SOCKS5 service active")
    }

    override fun onDestroy() {
        stopProxy()
        serviceReceiver?.let {
            try {
                unregisterReceiver(it)
            } catch (_: Exception) {}
        }
        serviceReceiver = null
        super.onDestroy()
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld != true) {
            try {
                val powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager
                wakeLock = powerManager?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TravonetVPN::SocksWakeLock")?.apply {
                    setReferenceCounted(false)
                    acquire(12 * 60 * 60 * 1000L) // 12 hours max timeout
                }
                Log.d(TAG, "Socks WakeLock acquired")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to acquire socks wake lock", e)
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
                wifiLock = wifiManager?.createWifiLock(mode, "TravonetVPN::SocksWifiLock")?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
                Log.d(TAG, "Socks WifiLock acquired")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to acquire socks wifi lock", e)
            }
        }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
                Log.d(TAG, "Socks WakeLock released")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to release socks wake lock", e)
        } finally {
            wakeLock = null
        }
        try {
            if (wifiLock?.isHeld == true) {
                wifiLock?.release()
                Log.d(TAG, "Socks WifiLock released")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to release socks wifi lock", e)
        } finally {
            wifiLock = null
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "TravonetVPN SOCKS5",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Статус SOCKS5 прокси TravonetVPN"
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun startForegroundServiceNotification(profileName: String, listenAddr: String, subtext: String) {
        val notification = buildNotification(profileName, listenAddr, subtext)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, 0)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(profileName: String, listenAddr: String, subtext: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, TravonetSocksService::class.java).apply {
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
            .setContentTitle("SOCKS5: $profileName")
            .setContentText("Прокси адрес: $listenAddr")
            .setSubText(subtext)
            .setOngoing(true)
            .setContentIntent(openPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Остановить", stopPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
