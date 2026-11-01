package com.travonet.wireguard.subscription

import com.travonet.wireguard.model.WgProfile
import com.travonet.wireguard.parser.WgConfigParser
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class SubscriptionResult(
    val title: String,
    val profiles: List<WgProfile>,
    val updateIntervalHours: Int?,
    val userInfo: String?
)

object SubscriptionFetcher {

    fun decodeBase64(input: String): ByteArray? {
        val sanitized = input.replace("\r", "").replace("\n", "").replace(" ", "").trim()
        if (sanitized.isEmpty()) return null

        // 1. Try java.util.Base64 (JVM unit tests and Android API 26+)
        try {
            return java.util.Base64.getDecoder().decode(sanitized)
        } catch (_: Exception) {}
        try {
            return java.util.Base64.getUrlDecoder().decode(sanitized)
        } catch (_: Exception) {}

        // Handle missing padding
        val rem = sanitized.length % 4
        if (rem != 0) {
            val padded = sanitized + "=".repeat(4 - rem)
            try {
                return java.util.Base64.getDecoder().decode(padded)
            } catch (_: Exception) {}
            try {
                return java.util.Base64.getUrlDecoder().decode(padded)
            } catch (_: Exception) {}
        }

        // 2. Fallback to android.util.Base64 if available
        try {
            return android.util.Base64.decode(sanitized, android.util.Base64.DEFAULT)
        } catch (_: Exception) {}
        try {
            return android.util.Base64.decode(sanitized, android.util.Base64.URL_SAFE)
        } catch (_: Exception) {}

        return null
    }

    fun parseProfileTitle(rawHeader: String?): String? {
        if (rawHeader.isNullOrBlank()) return null
        val trimmed = rawHeader.trim()
        if (trimmed.startsWith("base64:", ignoreCase = true)) {
            val b64 = trimmed.substring(7).trim()
            val decoded = decodeBase64(b64)
            if (decoded != null) {
                return String(decoded, StandardCharsets.UTF_8).trim()
            }
            return b64
        }
        return trimmed
    }

    fun parseSubscriptionBody(
        body: String,
        defaultTitle: String? = null,
        subscriptionUrl: String? = null
    ): List<WgProfile> {
        val trimmed = body.trim()
        if (trimmed.isEmpty()) return emptyList()

        // Standard subscriptions return a Base64-encoded string containing links or raw configs
        var textToParse = trimmed
        val decodedBytes = decodeBase64(trimmed)
        if (decodedBytes != null) {
            val decodedString = String(decodedBytes, StandardCharsets.UTF_8).trim()
            if (decodedString.contains("://") || decodedString.contains("[Interface]") || decodedString.contains("\n")) {
                textToParse = decodedString
            }
        }

        val profiles = mutableListOf<WgProfile>()
        var counter = 1

        val lines = textToParse.lines()
        val linkLines = lines.map { it.trim() }.filter { it.isNotBlank() && !it.startsWith("#") && !it.startsWith("//") }

        // If the whole decoded body is a single [Interface] config
        val isSingleIni = textToParse.contains("[Interface]", ignoreCase = true) && !textToParse.contains("vpn://")

        if (isSingleIni) {
            val name = defaultTitle ?: "Подписка"
            val profileId = if (!subscriptionUrl.isNullOrBlank()) {
                java.util.UUID.nameUUIDFromBytes("sub:${subscriptionUrl}_1".toByteArray()).toString()
            } else {
                java.util.UUID.randomUUID().toString()
            }
            profiles.add(
                WgConfigParser.parseProfile(
                    name = name,
                    rawConfig = textToParse,
                    id = profileId,
                    subscriptionUrl = subscriptionUrl
                )
            )
            return profiles
        }

        for (line in linkLines) {
            val profileId = if (!subscriptionUrl.isNullOrBlank()) {
                java.util.UUID.nameUUIDFromBytes("sub:${subscriptionUrl}_$counter".toByteArray()).toString()
            } else {
                java.util.UUID.randomUUID().toString()
            }

            if (line.startsWith("vpn://", ignoreCase = true)) {
                val fallbackName = if (defaultTitle != null && linkLines.size > 1) {
                    "$defaultTitle $counter"
                } else {
                    defaultTitle ?: "Профиль $counter"
                }
                val profile = WgConfigParser.parseProfile(
                    name = fallbackName,
                    rawConfig = line,
                    id = profileId,
                    subscriptionUrl = subscriptionUrl
                )
                if (profile.rawConfig.contains("[Interface]", ignoreCase = true)) {
                    profiles.add(profile)
                    counter++
                }
            } else if (line.startsWith("[Interface]", ignoreCase = true)) {
                val fallbackName = if (defaultTitle != null && linkLines.size > 1) {
                    "$defaultTitle $counter"
                } else {
                    defaultTitle ?: "Профиль $counter"
                }
                val profile = WgConfigParser.parseProfile(
                    name = fallbackName,
                    rawConfig = line,
                    id = profileId,
                    subscriptionUrl = subscriptionUrl
                )
                if (profile.rawConfig.contains("[Interface]", ignoreCase = true)) {
                    profiles.add(profile)
                    counter++
                }
            }
        }

        return profiles
    }

    private fun createInsecureSslContext(): SSLContext {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(certs: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(certs: Array<X509Certificate>, authType: String) {}
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, SecureRandom())
        return sslContext
    }

    /**
     * Загружает подписку X-UI по указанному URL (HTTP или HTTPS).
     * Поддерживает кастомные порты и самоподписанные сертификаты (часто используемые в X-UI).
     */
    @Throws(IOException::class)
    fun fetchSubscription(urlStr: String): SubscriptionResult {
        val url = URL(urlStr)
        val conn = url.openConnection() as HttpURLConnection
        conn.connectTimeout = 15000
        conn.readTimeout = 15000
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", "TravonetWG-Android/1.2.0")
        conn.setRequestProperty("Accept", "*/*")

        if (conn is HttpsURLConnection) {
            try {
                conn.sslSocketFactory = createInsecureSslContext().socketFactory
                conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            } catch (_: Exception) {}
        }

        conn.connect()
        val responseCode = conn.responseCode
        if (responseCode !in 200..299) {
            val errorBody = conn.errorStream?.bufferedReader(StandardCharsets.UTF_8)?.use { it.readText() } ?: ""
            conn.disconnect()
            throw IOException("Ошибка сервера HTTP $responseCode: ${conn.responseMessage}. $errorBody".trim())
        }

        val profileTitleRaw = conn.getHeaderField("Profile-Title")
        val title = parseProfileTitle(profileTitleRaw) ?: "Подписка"
        val intervalRaw = conn.getHeaderField("Profile-Update-Interval")
        val updateInterval = intervalRaw?.toIntOrNull()
        val userInfo = conn.getHeaderField("Subscription-Userinfo")

        val body = conn.inputStream.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
        conn.disconnect()

        val profiles = parseSubscriptionBody(body, title, urlStr)
        if (profiles.isEmpty()) {
            throw IOException("В подписке не найдено поддерживаемых конфигураций WireGuard / AmneziaWG")
        }

        return SubscriptionResult(
            title = title,
            profiles = profiles,
            updateIntervalHours = updateInterval,
            userInfo = userInfo
        )
    }
}
