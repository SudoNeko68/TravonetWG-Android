package com.travonet.wireguard.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import com.travonet.wireguard.model.EvasionStrategy
import com.travonet.wireguard.model.TunnelMode
import com.travonet.wireguard.model.TunnelState
import com.travonet.wireguard.model.TunnelStats
import com.travonet.wireguard.model.TunnelStatus
import com.travonet.wireguard.model.WgProfile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

object TunnelManager {
    private const val TAG = "TunnelManager"

    const val ACTION_TUNNEL_STATE_BROADCAST = "com.travonet.vpn.TUNNEL_STATE_BROADCAST"
    const val ACTION_TUNNEL_STATS_BROADCAST = "com.travonet.vpn.TUNNEL_STATS_BROADCAST"
    const val ACTION_CAPTCHA_BROADCAST = "com.travonet.vpn.CAPTCHA_BROADCAST"
    const val ACTION_QUERY_TUNNEL_STATE = "com.travonet.vpn.QUERY_TUNNEL_STATE"

    private const val PREFS_NAME = "tunnel_ipc_state"
    private const val KEY_STATUS = "status"
    private const val KEY_MESSAGE = "message"
    private const val KEY_PROFILE_NAME = "profile_name"
    private const val KEY_PROFILE_ID = "profile_id"
    private const val KEY_MODE = "mode"
    private const val KEY_STRATEGY_NAME = "strategy_name"

    @Volatile
    private var appContext: Context? = null

    private val _state = MutableStateFlow(TunnelState())
    val state: StateFlow<TunnelState> = _state.asStateFlow()

    private val _stats = MutableStateFlow(TunnelStats())
    val stats: StateFlow<TunnelStats> = _stats.asStateFlow()

    private val _captchaUrl = MutableStateFlow<String?>(null)
    val captchaUrl: StateFlow<String?> = _captchaUrl.asStateFlow()

    // Holds the active handle for VpnService or SOCKS5 (in :vpn process)
    var vpnHandle: Int = -1
    var socksHandle: Int = -1

    fun init(context: Context) {
        if (appContext == null) {
            appContext = context.applicationContext
            loadSavedState(context.applicationContext)
        }
    }

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private fun loadSavedState(context: Context) {
        try {
            val prefs = getPrefs(context)
            val statusStr = prefs.getString(KEY_STATUS, null) ?: return
            val rawStatus = try { TunnelStatus.valueOf(statusStr) } catch (_: Throwable) { TunnelStatus.DISCONNECTED }
            val status = if (rawStatus == TunnelStatus.CONNECTING || rawStatus == TunnelStatus.STOPPING) {
                TunnelStatus.DISCONNECTED
            } else {
                rawStatus
            }
            val message = prefs.getString(KEY_MESSAGE, "") ?: ""
            val profileName = prefs.getString(KEY_PROFILE_NAME, "") ?: ""
            val profileId = prefs.getString(KEY_PROFILE_ID, null)
            val modeStr = prefs.getString(KEY_MODE, TunnelMode.VPN.name) ?: TunnelMode.VPN.name
            val mode = try { TunnelMode.valueOf(modeStr) } catch (_: Throwable) { TunnelMode.VPN }
            val strategyName = prefs.getString(KEY_STRATEGY_NAME, "") ?: ""

            _state.value = TunnelState(
                status = status,
                message = message,
                profileName = profileName,
                profileId = profileId,
                mode = mode,
                strategyName = strategyName
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load saved tunnel IPC state", e)
        }
    }

    private fun saveCurrentState(context: Context, state: TunnelState) {
        try {
            getPrefs(context).edit().apply {
                putString(KEY_STATUS, state.status.name)
                putString(KEY_MESSAGE, state.message)
                putString(KEY_PROFILE_NAME, state.profileName)
                putString(KEY_PROFILE_ID, state.profileId)
                putString(KEY_MODE, state.mode.name)
                putString(KEY_STRATEGY_NAME, state.strategyName)
                apply()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to persist tunnel IPC state", e)
        }
    }

    fun showCaptcha(url: String) {
        _captchaUrl.value = url
        broadcastCaptcha(url)
    }

    fun hideCaptcha() {
        _captchaUrl.value = null
        broadcastCaptcha(null)
    }

    private fun broadcastCaptcha(url: String?) {
        val ctx = appContext ?: return
        try {
            val intent = Intent(ACTION_CAPTCHA_BROADCAST).apply {
                setPackage(ctx.packageName)
                putExtra("url", url)
            }
            ctx.sendBroadcast(intent)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to broadcast captcha", e)
        }
    }

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
        val newState = TunnelState(
            status = status,
            message = message,
            profileName = if (profileName.isNotEmpty()) profileName else _state.value.profileName,
            profileId = if (status == TunnelStatus.DISCONNECTED) null else (profileId ?: _state.value.profileId),
            mode = mode,
            strategyName = if (strategyName.isNotEmpty()) strategyName else _state.value.strategyName
        )
        _state.value = newState

        appContext?.let { ctx ->
            saveCurrentState(ctx, newState)
            try {
                val intent = Intent(ACTION_TUNNEL_STATE_BROADCAST).apply {
                    setPackage(ctx.packageName)
                    putExtra("status", newState.status.name)
                    putExtra("message", newState.message)
                    putExtra("profileName", newState.profileName)
                    putExtra("profileId", newState.profileId)
                    putExtra("mode", newState.mode.name)
                    putExtra("strategyName", newState.strategyName)
                }
                ctx.sendBroadcast(intent)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to broadcast state", e)
            }
        }
    }

    fun updateStats(newStats: TunnelStats) {
        _stats.value = newStats
        appContext?.let { ctx ->
            try {
                val intent = Intent(ACTION_TUNNEL_STATS_BROADCAST).apply {
                    setPackage(ctx.packageName)
                    putExtra("txBytes", newStats.txBytes)
                    putExtra("rxBytes", newStats.rxBytes)
                    putExtra("lastHandshakeSec", newStats.lastHandshakeSec)
                }
                ctx.sendBroadcast(intent)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to broadcast stats", e)
            }
        }
    }

    fun broadcastCurrentState() {
        val curState = _state.value
        val curStats = _stats.value
        appContext?.let { ctx ->
            try {
                val stateIntent = Intent(ACTION_TUNNEL_STATE_BROADCAST).apply {
                    setPackage(ctx.packageName)
                    putExtra("status", curState.status.name)
                    putExtra("message", curState.message)
                    putExtra("profileName", curState.profileName)
                    putExtra("profileId", curState.profileId)
                    putExtra("mode", curState.mode.name)
                    putExtra("strategyName", curState.strategyName)
                }
                ctx.sendBroadcast(stateIntent)

                val statsIntent = Intent(ACTION_TUNNEL_STATS_BROADCAST).apply {
                    setPackage(ctx.packageName)
                    putExtra("txBytes", curStats.txBytes)
                    putExtra("rxBytes", curStats.rxBytes)
                    putExtra("lastHandshakeSec", curStats.lastHandshakeSec)
                }
                ctx.sendBroadcast(statsIntent)

                _captchaUrl.value?.let { broadcastCaptcha(it) }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to send current state broadcast", e)
            }
        }
    }

    fun resetStats() {
        updateStats(TunnelStats())
    }

    fun registerUiReceiver(context: Context): BroadcastReceiver {
        init(context)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                when (intent?.action) {
                    ACTION_TUNNEL_STATE_BROADCAST -> {
                        val statusStr = intent.getStringExtra("status") ?: return
                        val status = try { TunnelStatus.valueOf(statusStr) } catch (_: Throwable) { return }
                        val message = intent.getStringExtra("message") ?: ""
                        val profileName = intent.getStringExtra("profileName") ?: ""
                        val profileId = intent.getStringExtra("profileId")
                        val modeStr = intent.getStringExtra("mode") ?: TunnelMode.VPN.name
                        val mode = try { TunnelMode.valueOf(modeStr) } catch (_: Throwable) { TunnelMode.VPN }
                        val strategyName = intent.getStringExtra("strategyName") ?: ""

                        _state.value = TunnelState(
                            status = status,
                            message = message,
                            profileName = profileName,
                            profileId = profileId,
                            mode = mode,
                            strategyName = strategyName
                        )
                    }
                    ACTION_TUNNEL_STATS_BROADCAST -> {
                        val tx = intent.getLongExtra("txBytes", 0L)
                        val rx = intent.getLongExtra("rxBytes", 0L)
                        val hs = intent.getLongExtra("lastHandshakeSec", 0L)
                        _stats.value = TunnelStats(txBytes = tx, rxBytes = rx, lastHandshakeSec = hs)
                    }
                    ACTION_CAPTCHA_BROADCAST -> {
                        val url = intent.getStringExtra("url")
                        _captchaUrl.value = url
                    }
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction(ACTION_TUNNEL_STATE_BROADCAST)
            addAction(ACTION_TUNNEL_STATS_BROADCAST)
            addAction(ACTION_CAPTCHA_BROADCAST)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }

        // Query running service in :vpn process for current status
        queryTunnelState(context)

        return receiver
    }

    fun queryTunnelState(context: Context) {
        try {
            val queryIntent = Intent(ACTION_QUERY_TUNNEL_STATE).apply {
                setPackage(context.packageName)
            }
            context.sendBroadcast(queryIntent)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to query tunnel state", e)
        }
    }

    fun registerServiceReceiver(context: Context): BroadcastReceiver {
        init(context)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                if (intent?.action == ACTION_QUERY_TUNNEL_STATE) {
                    broadcastCurrentState()
                }
            }
        }
        val filter = IntentFilter(ACTION_QUERY_TUNNEL_STATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
        return receiver
    }

    fun start(context: Context, profile: WgProfile, fallbackStrategy: EvasionStrategy, mode: TunnelMode) {
        init(context)
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

        val targetProfileId = profile.id
        CoroutineScope(Dispatchers.Main).launch {
            delay(25000)
            if (_state.value.status == TunnelStatus.CONNECTING && _state.value.profileId == targetProfileId) {
                Log.w(TAG, "Connection attempt timed out for profile: $targetProfileId")
                updateState(TunnelStatus.ERROR, "Превышено время ожидания подключения")
            }
        }

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
        init(context)
        val currentMode = _state.value.mode
        val wasConnecting = (_state.value.status == TunnelStatus.CONNECTING)
        updateState(status = if (wasConnecting) TunnelStatus.DISCONNECTED else TunnelStatus.STOPPING)

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

        // Failsafe watchdog: if state is still STOPPING after 2s, force DISCONNECTED
        CoroutineScope(Dispatchers.Main).launch {
            delay(2000)
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
