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

        // 1. Decode outer Base64 if present
        var textToParse = trimmed
        val decodedBytes = decodeBase64(trimmed)
        if (decodedBytes != null) {
            val decodedString = String(decodedBytes, StandardCharsets.UTF_8).trim()
            if (decodedString.contains("://") || decodedString.contains("[Interface]", ignoreCase = true) || decodedString.contains("\n")) {
                textToParse = decodedString
            }
        }


        val profiles = mutableListOf<WgProfile>()
        var counter = 1

        fun makeProfileId(): String {
            return if (!subscriptionUrl.isNullOrBlank()) {
                java.util.UUID.nameUUIDFromBytes("sub:${subscriptionUrl}_$counter".toByteArray()).toString()
            } else {
                java.util.UUID.randomUUID().toString()
            }
        }

        // 2. Check if textToParse is multi-config INI containing one or more [Interface] sections
        val hasUrlSchemes = textToParse.contains("vpn://", ignoreCase = true) ||
                textToParse.contains("wireguard://", ignoreCase = true) ||
                textToParse.contains("wg://", ignoreCase = true)

        if (!hasUrlSchemes && textToParse.contains("[Interface]", ignoreCase = true)) {
            val blocks = splitIniConfigs(textToParse)
            for (block in blocks) {
                val fallbackName = if (defaultTitle != null && blocks.size > 1) {
                    "$defaultTitle $counter"
                } else {
                    defaultTitle ?: "Профиль $counter"
                }
                val blockName = extractNameFromIniBlock(block) ?: fallbackName
                val profile = WgConfigParser.parseProfile(
                    name = blockName,
                    rawConfig = block,
                    id = makeProfileId(),
                    subscriptionUrl = subscriptionUrl
                )
                if (profile.rawConfig.contains("[Interface]", ignoreCase = true)) {
                    profiles.add(profile)
                    counter++
                }
            }
            if (profiles.isNotEmpty()) return profiles
        }

        // 3. Otherwise, parse line by line (URLs, Base64 chunks, individual configs)
        val lines = textToParse.lines().map { it.trim() }.filter { it.isNotBlank() && !it.startsWith("#") && !it.startsWith("//") }
        for (line in lines) {
            val fallbackName = if (defaultTitle != null && lines.size > 1) {
                "$defaultTitle $counter"
            } else {
                defaultTitle ?: "Профиль $counter"
            }

            // Check if line is any supported proxy link (VLESS, VMess, Trojan, SS, TUIC, Hysteria 2, ShadowTLS, WireGuard, AmneziaWG)
            if (com.travonet.wireguard.parser.ProxyLinkParser.isProxyLink(line)) {
                val profile = com.travonet.wireguard.parser.ProxyLinkParser.parse(
                    rawUri = line,
                    fallbackName = fallbackName,
                    subUrl = subscriptionUrl,
                    id = makeProfileId()
                )
                if (profile != null) {
                    profiles.add(profile)
                    counter++
                    continue
                }
            }

            // Fallback for Base64 encoded line or INI block
            val decodedLine = tryDecodeBase64(line)
            if (decodedLine != null) {
                if (com.travonet.wireguard.parser.ProxyLinkParser.isProxyLink(decodedLine)) {
                    val profile = com.travonet.wireguard.parser.ProxyLinkParser.parse(
                        rawUri = decodedLine,
                        fallbackName = fallbackName,
                        subUrl = subscriptionUrl,
                        id = makeProfileId()
                    )
                    if (profile != null) {
                        profiles.add(profile)
                        counter++
                        continue
                    }
                } else if (decodedLine.contains("[Interface]", ignoreCase = true)) {
                    val blocks = splitIniConfigs(decodedLine)
                    for (block in blocks) {
                        val fallbackBlockName = if (defaultTitle != null && blocks.size > 1) {
                            "$defaultTitle $counter"
                        } else {
                            fallbackName
                        }
                        val blockName = extractNameFromIniBlock(block) ?: fallbackBlockName
                        val profile = WgConfigParser.parseProfile(
                            name = blockName,
                            rawConfig = block,
                            id = makeProfileId(),
                            subscriptionUrl = subscriptionUrl
                        )
                        if (profile.rawConfig.contains("[Interface]", ignoreCase = true)) {
                            profiles.add(profile)
                            counter++
                        }
                    }
                }
            }
        }

        return profiles
    }

    private fun splitIniConfigs(text: String): List<String> {
        val lines = text.lines()
        val blocks = mutableListOf<String>()
        val currentBlock = StringBuilder()
        val pendingLeadingLines = mutableListOf<String>()
        var hasSeenInterfaceInCurrent = false

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.equals("[Interface]", ignoreCase = true)) {
                if (hasSeenInterfaceInCurrent) {
                    blocks.add(currentBlock.toString().trim())
                    currentBlock.clear()
                }
                for (pending in pendingLeadingLines) {
                    currentBlock.appendLine(pending)
                }
                pendingLeadingLines.clear()
                hasSeenInterfaceInCurrent = true
                currentBlock.appendLine(line)
            } else if (!hasSeenInterfaceInCurrent) {
                pendingLeadingLines.add(line)
            } else {
                if (trimmed.startsWith("#") || trimmed.startsWith(";") || trimmed.isEmpty()) {
                    pendingLeadingLines.add(line)
                } else {
                    for (pending in pendingLeadingLines) {
                        currentBlock.appendLine(pending)
                    }
                    pendingLeadingLines.clear()
                    currentBlock.appendLine(line)
                }
            }
        }
        for (pending in pendingLeadingLines) {
            currentBlock.appendLine(pending)
        }
        if (currentBlock.isNotBlank() && hasSeenInterfaceInCurrent) {
            blocks.add(currentBlock.toString().trim())
        }
        return if (blocks.isNotEmpty()) blocks else listOf(text.trim())
    }

    private fun extractNameFromIniBlock(block: String): String? {
        val lines = block.lines()
        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.startsWith("#") && !trimmed.startsWith("# Injected")) {
                val comment = trimmed.substring(1).trim()
                if (comment.isNotBlank() && !comment.startsWith("---") && !comment.contains("=")) {
                    return comment
                }
            }
            if (trimmed.equals("[Interface]", ignoreCase = true)) {
                break
            }
        }
        return null
    }

    private fun tryDecodeBase64(input: String): String? {
        val sanitized = input.replace("\r", "").replace("\n", "").replace(" ", "").trim()
        if (sanitized.isEmpty()) return null
        return try {
            val bytes = decodeBase64(sanitized)
            if (bytes != null && bytes.isNotEmpty()) {
                String(bytes, StandardCharsets.UTF_8)
            } else null
        } catch (_: Exception) {
            null
        }
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
        conn.setRequestProperty("User-Agent", "TravonetVPN-Android/2.0")
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
