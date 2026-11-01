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

    // Holds the active handle for VpnService or SOCKS5
    var vpnHandle: Int = -1
    var socksHandle: Int = -1

    fun updateState(status: TunnelStatus, message: String = "", profileName: String = "", mode: TunnelMode = TunnelMode.VPN, strategyName: String = "") {
        _state.value = TunnelState(
            status = status,
            message = message,
            profileName = if (profileName.isNotEmpty()) profileName else _state.value.profileName,
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
        if (_state.value.status == TunnelStatus.CONNECTED || _state.value.status == TunnelStatus.CONNECTING) {
            return
        }

        val strategyNameToReport = if (profile.hasEmbeddedStrategy) {
            "Из конфига: ${profile.embeddedStrategy}"
        } else {
            fallbackStrategy.name
        }

        updateState(
            status = TunnelStatus.CONNECTING,
            profileName = profile.name,
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
            try {
                org.travonet.backend.GoBackend.wgTurnOff(currentVpnHandle)
            } catch (e: Exception) {
                // ignore
            }
            vpnHandle = -1
        }
        val currentSocksHandle = socksHandle
        if (currentSocksHandle >= 0) {
            try {
                org.travonet.backend.GoBackend.wgStopSocks5(currentSocksHandle)
            } catch (e: Exception) {
                // ignore
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
