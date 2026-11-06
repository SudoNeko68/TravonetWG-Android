package com.travonet.wireguard

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.travonet.wireguard.model.EvasionStrategy
import com.travonet.wireguard.model.TunnelMode
import com.travonet.wireguard.model.WgProfile
import com.travonet.wireguard.service.TunnelManager
import com.travonet.wireguard.ui.MainScreen
import com.travonet.wireguard.ui.theme.TravonetWGTheme

class MainActivity : ComponentActivity() {

    private var pendingProfile: WgProfile? = null
    private var pendingStrategy: EvasionStrategy? = null
    private var pendingMode: TunnelMode? = null
    private var pendingStart: (() -> Unit)? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val profile = pendingProfile
            val strategy = pendingStrategy
            val mode = pendingMode
            if (profile != null && strategy != null && mode != null) {
                TunnelManager.start(this, profile, strategy, mode)
            }
        } else {
            Toast.makeText(this, "Разрешение на создание VPN отклонено", Toast.LENGTH_SHORT).show()
        }
        pendingProfile = null
        pendingStrategy = null
        pendingMode = null
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        // Notification permission granted/denied
    }

    /**
     * Android 17 (API 37) блокирует доступ к локальной сети без
     * ACCESS_LOCAL_NETWORK: sendmsg возвращает EPERM. Публичные серверы
     * работают и без него, поэтому запуск не отменяем при отказе.
     */
    @Suppress("InlinedApi")
    private val localNetworkPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        val action = pendingStart
        pendingStart = null
        action?.invoke()
    }

    private fun withLocalNetworkPermission(action: () -> Unit) {
        if (Build.VERSION.SDK_INT >= 37 && ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.ACCESS_LOCAL_NETWORK
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            pendingStart = action
            localNetworkPermissionLauncher.launch(Manifest.permission.ACCESS_LOCAL_NETWORK)
        } else {
            action()
        }
    }

    private var uiReceiver: android.content.BroadcastReceiver? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        TunnelManager.init(this)
        uiReceiver = TunnelManager.registerUiReceiver(this)
        checkBatteryOptimizationOnce()

        setContent {
            TravonetWGTheme {
                MainScreen(
                    onRequestStartTunnel = { profile, strategy, mode ->
                        // Ask for notification permission only when the user
                        // actually starts a foreground tunnel, not on every
                        // cold app start.
                        checkNotificationPermission()
                        withLocalNetworkPermission {
                            when (mode) {
                                TunnelMode.VPN -> {
                                    val vpnIntent = VpnService.prepare(this)
                                    if (vpnIntent != null) {
                                        pendingProfile = profile
                                        pendingStrategy = strategy
                                        pendingMode = mode
                                        vpnPermissionLauncher.launch(vpnIntent)
                                    } else {
                                        TunnelManager.start(this, profile, strategy, mode)
                                    }
                                }
                                TunnelMode.SOCKS5 -> {
                                    // Zero-root / Zero-permission mode
                                    TunnelManager.start(this, profile, strategy, mode)
                                }
                            }
                        }
                    }
                )
            }
        }
    }

    private fun checkNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun checkBatteryOptimizationOnce() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val prefs = getSharedPreferences("travonet_prefs", Context.MODE_PRIVATE)
            if (prefs.getBoolean("battery_optimization_prompted", false)) return

            val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager
            if (pm != null && !pm.isIgnoringBatteryOptimizations(packageName)) {
                try {
                    prefs.edit().putBoolean("battery_optimization_prompted", true).apply()
                    val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                        data = Uri.parse("package:$packageName")
                    }
                    startActivity(intent)
                } catch (_: Exception) {}
            }
        }
    }

    override fun onResume() {
        super.onResume()
        TunnelManager.queryTunnelState(this)
    }

    override fun onDestroy() {
        super.onDestroy()
        uiReceiver?.let {
            try {
                unregisterReceiver(it)
            } catch (_: Exception) {}
        }
        uiReceiver = null
    }
}