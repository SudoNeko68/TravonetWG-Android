package com.travonet.wireguard.model

import org.json.JSONObject
import java.util.UUID

enum class TunnelMode(val displayName: String) {
    VPN("VPN (Системный TUN)"),
    SOCKS5("SOCKS5 (127.0.0.1:1080)")
}

enum class TunnelStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    STOPPING,
    ERROR
}

/**
 * Откуда брать релей для анонимной регистрации WARP.
 * AUTO — URL/токен, зашитые в сборку; CUSTOM — введённые пользователем;
 * NONE — регистрироваться напрямую через api.cloudflareclient.com.
 */
enum class WarpRelayMode {
    AUTO,
    CUSTOM,
    NONE
}

data class TunnelState(
    val status: TunnelStatus = TunnelStatus.DISCONNECTED,
    val message: String = "",
    val profileName: String = "",
    val mode: TunnelMode = TunnelMode.VPN,
    val strategyName: String = ""
)

data class TunnelStats(
    val txBytes: Long = 0,
    val rxBytes: Long = 0,
    val lastHandshakeSec: Long = 0
) {
    fun formattedTx(): String = formatBytes(txBytes)
    fun formattedRx(): String = formatBytes(rxBytes)

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format(java.util.Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format(java.util.Locale.US, "%.2f MB", mb)
        val gb = mb / 1024.0
        return String.format(java.util.Locale.US, "%.2f GB", gb)
    }
}

data class WgProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val rawConfig: String,
    val endpoint: String = "",
    val address: String = "",
    val allowedIps: String = "",
    val dns: String = "",
    val mtu: Int = 1280,
    val hasEmbeddedStrategy: Boolean = false,
    val embeddedStrategy: String? = null,
    val subscriptionUrl: String? = null
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("id", id)
            put("name", name)
            put("rawConfig", rawConfig)
            put("endpoint", endpoint)
            put("address", address)
            put("allowedIps", allowedIps)
            put("dns", dns)
            put("mtu", mtu)
            put("hasEmbeddedStrategy", hasEmbeddedStrategy)
            put("embeddedStrategy", embeddedStrategy ?: "")
            if (!subscriptionUrl.isNullOrBlank()) {
                put("subscriptionUrl", subscriptionUrl)
            }
        }
    }

    companion object {
        fun fromJson(json: JSONObject): WgProfile {
            val embedded = json.optString("embeddedStrategy", "")
            val subUrl = json.optString("subscriptionUrl", "").takeIf { it.isNotBlank() }
            return WgProfile(
                id = json.optString("id", UUID.randomUUID().toString()),
                name = json.optString("name", "Unnamed Profile"),
                rawConfig = json.optString("rawConfig", ""),
                endpoint = json.optString("endpoint", ""),
                address = json.optString("address", ""),
                allowedIps = json.optString("allowedIps", ""),
                dns = json.optString("dns", ""),
                mtu = json.optInt("mtu", 1280),
                hasEmbeddedStrategy = json.optBoolean("hasEmbeddedStrategy", false),
                embeddedStrategy = if (embedded.isNotEmpty()) embedded else null,
                subscriptionUrl = subUrl
            )
        }
    }
}

data class EvasionStrategy(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val description: String,
    val dsl: String,
    val fakeTtl: String = "auto",
    val preJunk: Int = 64,
    val normalTtl: Int = 64,
    val isCustom: Boolean = false
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("id", id)
            put("name", name)
            put("description", description)
            put("dsl", dsl)
            put("fakeTtl", fakeTtl)
            put("preJunk", preJunk)
            put("normalTtl", normalTtl)
            put("isCustom", isCustom)
        }
    }

    companion object {
        fun fromJson(json: JSONObject): EvasionStrategy {
            return EvasionStrategy(
                id = json.optString("id", UUID.randomUUID().toString()),
                name = json.optString("name", "Custom Strategy"),
                description = json.optString("description", ""),
                dsl = json.optString("dsl", ""),
                fakeTtl = json.optString("fakeTtl", "auto"),
                preJunk = json.optInt("preJunk", 64),
                normalTtl = json.optInt("normalTtl", 64),
                isCustom = json.optBoolean("isCustom", true)
            )
        }
    }
}

data class Subscription(
    val url: String,
    val title: String,
    val lastUpdate: Long = 0L,
    val updateIntervalHours: Int? = null,
    val uploadBytes: Long? = null,
    val downloadBytes: Long? = null,
    val totalBytes: Long? = null,
    val expireTimeSec: Long? = null
) {
    fun formattedLastUpdate(): String {
        if (lastUpdate <= 0L) return "Никогда"
        val sdf = java.text.SimpleDateFormat("dd.MM.yyyy HH:mm", java.util.Locale.getDefault())
        return sdf.format(java.util.Date(lastUpdate))
    }

    fun formattedTraffic(): String? {
        val total = totalBytes ?: return null
        val used = (uploadBytes ?: 0L) + (downloadBytes ?: 0L)
        val usedStr = formatBytes(used)
        val totalStr = if (total <= 0) "∞" else formatBytes(total)
        return "$usedStr / $totalStr"
    }

    fun formattedExpire(): String? {
        val exp = expireTimeSec ?: return null
        if (exp <= 0L) return null
        val sdf = java.text.SimpleDateFormat("dd.MM.yyyy", java.util.Locale.getDefault())
        return "Истекает: " + sdf.format(java.util.Date(exp * 1000L))
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format(java.util.Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format(java.util.Locale.US, "%.1f MB", mb)
        val gb = mb / 1024.0
        if (gb < 1024) return String.format(java.util.Locale.US, "%.1f GB", gb)
        val tb = gb / 1024.0
        return String.format(java.util.Locale.US, "%.1f TB", tb)
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("url", url)
            put("title", title)
            put("lastUpdate", lastUpdate)
            if (updateIntervalHours != null) put("updateIntervalHours", updateIntervalHours)
            if (uploadBytes != null) put("uploadBytes", uploadBytes)
            if (downloadBytes != null) put("downloadBytes", downloadBytes)
            if (totalBytes != null) put("totalBytes", totalBytes)
            if (expireTimeSec != null) put("expireTimeSec", expireTimeSec)
        }
    }

    companion object {
        fun parseUserInfo(userInfo: String?): ParsedUserInfo {
            var upload: Long? = null
            var download: Long? = null
            var total: Long? = null
            var expire: Long? = null
            if (!userInfo.isNullOrBlank()) {
                val parts = userInfo.split(";")
                for (part in parts) {
                    val kv = part.trim().split("=")
                    if (kv.size == 2) {
                        val key = kv[0].trim().lowercase()
                        val value = kv[1].trim().toLongOrNull()
                        when (key) {
                            "upload" -> upload = value
                            "download" -> download = value
                            "total" -> total = value
                            "expire" -> expire = value
                        }
                    }
                }
            }
            return ParsedUserInfo(upload, download, total, expire)
        }

        fun fromJson(json: JSONObject): Subscription {
            return Subscription(
                url = json.optString("url", ""),
                title = json.optString("title", "Подписка"),
                lastUpdate = json.optLong("lastUpdate", 0L),
                updateIntervalHours = if (json.has("updateIntervalHours")) json.optInt("updateIntervalHours") else null,
                uploadBytes = if (json.has("uploadBytes")) json.optLong("uploadBytes") else null,
                downloadBytes = if (json.has("downloadBytes")) json.optLong("downloadBytes") else null,
                totalBytes = if (json.has("totalBytes")) json.optLong("totalBytes") else null,
                expireTimeSec = if (json.has("expireTimeSec")) json.optLong("expireTimeSec") else null
            )
        }
    }
}

data class ParsedUserInfo(
    val upload: Long?,
    val download: Long?,
    val total: Long?,
    val expire: Long?
)

