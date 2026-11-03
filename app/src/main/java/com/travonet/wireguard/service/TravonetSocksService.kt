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
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.travonet.backend.GoBackend

class TravonetSocksService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO)
    private var startJob: Job? = null
    private var statsJob: Job? = null

    companion object {
        const val TAG = "TravonetSocks"
        const val ACTION_START = "com.travonet.wireguard.action.START_SOCKS"
        const val ACTION_STOP = "com.travonet.wireguard.action.STOP_SOCKS"
        const val EXTRA_PROFILE_ID = "profile_id"
        private const val NOTIFICATION_ID = 1002
        private const val CHANNEL_ID = "travonet_socks_channel"
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
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
            val repository = AppRepository(this)
            val profile = repository.getProfiles().firstOrNull { it.id == profileId }
                ?: repository.getSelectedProfile()

            if (profile == null) {
                TunnelManager.updateState(TunnelStatus.ERROR, "Профиль не найден")
                stopSelf()
                return START_NOT_STICKY
            }

            val listenAddr = repository.getSocksListenAddr()
            // Immediately start foreground notification to satisfy Android Foreground Service watchdog
            startForegroundServiceNotification(profile.name, listenAddr, "Запуск SOCKS5...")

            val strategy = repository.getSelectedStrategy()
            startProxy(profile, strategy, listenAddr)
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
                if (TunnelManager.socksHandle >= 0) {
                    try {
                        GoBackend.wgStopSocks5(TunnelManager.socksHandle)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error stopping previous socks", e)
                    }
                    TunnelManager.socksHandle = -1
                }

                val preparedConfig = WgConfigParser.prepareConfigForLaunch(profile, strategy)

                val handle = GoBackend.wgStartSocks5(listenAddr, preparedConfig)
                if (handle < 0) {
                    TunnelManager.updateState(TunnelStatus.ERROR, "Ошибка запуска SOCKS5 прокси (Код: $handle)")
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

                startForegroundServiceNotification(profile.name, listenAddr, "Прокси активен на $listenAddr")
                startStatsPolling(handle, profile.name, listenAddr)

            } catch (e: kotlinx.coroutines.CancellationException) {
                Log.i(TAG, "startProxy was cancelled")
                TunnelManager.socksHandle = -1
                TunnelManager.updateState(TunnelStatus.DISCONNECTED)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            } catch (e: Throwable) {
                Log.e(TAG, "Error starting socks proxy", e)
                TunnelManager.socksHandle = -1
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

    private fun stopProxy() {
        startJob?.cancel()
        startJob = null
        statsJob?.cancel()
        statsJob = null

        val handle = TunnelManager.socksHandle
        if (handle >= 0) {
            try {
                GoBackend.wgStopSocks5(handle)
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping socks", e)
            }
            TunnelManager.socksHandle = -1
        }

        TunnelManager.updateState(TunnelStatus.DISCONNECTED)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "TravonetWG SOCKS5",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Статус SOCKS5 прокси TravonetWG"
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
