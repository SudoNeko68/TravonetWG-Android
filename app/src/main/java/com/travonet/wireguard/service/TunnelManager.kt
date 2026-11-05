package com.travonet.wireguard.service

import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.travonet.wireguard.model.EvasionStrategy
import com.travonet.wireguard.model.TunnelMode
import com.travonet.wireguard.model.TunnelState
import com.travonet.wireguard.model.TunnelStats
import com.travonet.wireguard.model.TunnelStatus
import com.travonet.wireguard.model.WgProfile
import com.travonet.wireguard.parser.WgConfigParser
import com.travonet.wireguard.repository.AppRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

object TunnelManager {
    private val _state = MutableStateFlow(TunnelState())
    val state: StateFlow<TunnelState> = _state.asStateFlow()

    private val _stats = MutableStateFlow(TunnelStats())
    val stats: StateFlow<TunnelStats> = _stats.asStateFlow()

    private val _captchaUrl = MutableStateFlow<String?>(null)
    val captchaUrl: StateFlow<String?> = _captchaUrl.asStateFlow()

    fun showCaptcha(url: String) {
        _captchaUrl.value = url
    }

    fun hideCaptcha() {
        _captchaUrl.value = null
    }

    // Holds the active handle for VpnService or SOCKS5
    var vpnHandle: Int = -1
    var socksHandle: Int = -1

    fun updateState(
        status: TunnelStatus,
        message: String = "",
        profileName: String = "",
        profileId: String? = null,
        mode: TunnelMode = TunnelMode.VPN,
        strategyName: String = ""
    ) {
        if (status == TunnelStatus.DISCONNECTED || status == TunnelStatus.ERROR) {
            hideCaptcha()
        }
        _state.value = TunnelState(
            status = status,
            message = message,
            profileName = if (profileName.isNotEmpty()) profileName else _state.value.profileName,
            profileId = if (status == TunnelStatus.DISCONNECTED) null else (profileId ?: _state.value.profileId),
            mode = mode,
            strategyName = if (strategyName.isNotEmpty()) strategyName else _state.value.strategyName
        )
    }

    fun updateStats(newStats: TunnelStats) {
        _stats.value = newStats
    }

    fun resetStats() {
        _stats.value = TunnelStats()
    }

    fun start(context: Context, profile: WgProfile, fallbackStrategy: EvasionStrategy, mode: TunnelMode) {
        if (_state.value.status == TunnelStatus.CONNECTING || _state.value.status == TunnelStatus.STOPPING) {
            return
        }

        if (_state.value.status == TunnelStatus.CONNECTED) {
            if (_state.value.profileId == profile.id && _state.value.mode == mode) {
                return
            }
            // Seamless switch to another profile or mode: cleanly stop current tunnel first
            stop(context)
            CoroutineScope(Dispatchers.Main).launch {
                delay(350)
                startInternal(context, profile, fallbackStrategy, mode)
            }
            return
        }

        startInternal(context, profile, fallbackStrategy, mode)
    }

    private fun startInternal(context: Context, profile: WgProfile, fallbackStrategy: EvasionStrategy, mode: TunnelMode) {
        val strategyNameToReport = if (profile.hasEmbeddedStrategy) {
            "Из конфига: ${profile.embeddedStrategy}"
        } else {
            fallbackStrategy.name
        }

        updateState(
            status = TunnelStatus.CONNECTING,
            profileName = profile.name,
            profileId = profile.id,
            mode = mode,
            strategyName = strategyNameToReport
        )
        resetStats()

        when (mode) {
            TunnelMode.VPN -> {
                val intent = Intent(context, TravonetVpnService::class.java).apply {
                    action = TravonetVpnService.ACTION_START
                    putExtra(TravonetVpnService.EXTRA_PROFILE_ID, profile.id)
                }
                androidx.core.content.ContextCompat.startForegroundService(context, intent)
            }
            TunnelMode.SOCKS5 -> {
                val intent = Intent(context, TravonetSocksService::class.java).apply {
                    action = TravonetSocksService.ACTION_START
                    putExtra(TravonetSocksService.EXTRA_PROFILE_ID, profile.id)
                }
                androidx.core.content.ContextCompat.startForegroundService(context, intent)
            }
        }
    }

    fun stop(context: Context) {
        val currentMode = _state.value.mode
        updateState(status = TunnelStatus.STOPPING)

        // Emergency safeguard: immediately terminate native handles if active
        val currentVpnHandle = vpnHandle
        if (currentVpnHandle >= 0) {
            if (currentVpnHandle in 0 until 90000) {
                try {
                    org.travonet.backend.GoBackend.wgTurnOff(currentVpnHandle)
                } catch (e: Exception) {
                    // ignore
                }
            }
            vpnHandle = -1
        }
        if (com.freevpn.coreloader.NativeCoreBridge.isProxyRunningNative()) {
            try {
                com.freevpn.coreloader.NativeCoreBridge.stopCoreNative()
            } catch (e: Exception) {
                // ignore
            }
        }
        val currentSocksHandle = socksHandle
        if (currentSocksHandle >= 0) {
            if (currentSocksHandle in 0 until 90000) {
                try {
                    org.travonet.backend.GoBackend.wgStopSocks5(currentSocksHandle)
                } catch (e: Exception) {
                    // ignore
                }
            }
            socksHandle = -1
        }

        when (currentMode) {
            TunnelMode.VPN -> {
                val intent = Intent(context, TravonetVpnService::class.java).apply {
                    action = TravonetVpnService.ACTION_STOP
                }
                context.startService(intent)
            }
            TunnelMode.SOCKS5 -> {
                val intent = Intent(context, TravonetSocksService::class.java).apply {
                    action = TravonetSocksService.ACTION_STOP
                }
                context.startService(intent)
            }
        }

        // Failsafe watchdog: if state is still STOPPING or CONNECTING after 1.5s, force DISCONNECTED
        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Main).launch {
            kotlinx.coroutines.delay(1500)
            if (_state.value.status == TunnelStatus.STOPPING || _state.value.status == TunnelStatus.CONNECTING) {
                updateState(TunnelStatus.DISCONNECTED)
            }
        }
    }

    fun parseUapiStats(uapi: String?): TunnelStats {
        if (uapi.isNullOrBlank()) return TunnelStats()
        var tx = 0L
        var rx = 0L
        var handshake = 0L
        uapi.lines().forEach { line ->
            val parts = line.split("=", limit = 2)
            if (parts.size == 2) {
                when (parts[0].trim()) {
                    "tx_bytes" -> tx += parts[1].trim().toLongOrNull() ?: 0L
                    "rx_bytes" -> rx += parts[1].trim().toLongOrNull() ?: 0L
                    "last_handshake_time_sec" -> {
                        val sec = parts[1].trim().toLongOrNull() ?: 0L
                        if (sec > handshake) handshake = sec
                    }
                }
            }
        }
        return TunnelStats(txBytes = tx, rxBytes = rx, lastHandshakeSec = handshake)
    }
}
