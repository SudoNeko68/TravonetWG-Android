package com.travonet.wireguard.parser

import com.travonet.wireguard.model.DefaultStrategies
import com.travonet.wireguard.model.EvasionStrategy
import com.travonet.wireguard.model.WgProfile

object WgConfigParser {

    data class ParsedInterface(
        val privateKey: String = "",
        val addresses: List<String> = emptyList(),
        val dnsServers: List<String> = emptyList(),
        val mtu: Int = 1280,
        val strategy: String? = null,
        val fakeTtl: String? = null,
        val preJunk: Int? = null,
        val normalTtl: Int? = null
    )

    data class ParsedPeer(
        val publicKey: String = "",
        val endpoint: String = "",
        val allowedIps: List<String> = emptyList(),
        val persistentKeepalive: Int? = null
    )

    data class ParsedConfig(
        val iface: ParsedInterface,
        val peers: List<ParsedPeer>
    )

    fun parse(rawContent: String): ParsedConfig {
        var currentSection = ""
        var privateKey = ""
        val addresses = mutableListOf<String>()
        val dnsServers = mutableListOf<String>()
        var mtu = 1280
        var strategy: String? = null
        var fakeTtl: String? = null
        var preJunk: Int? = null
        var normalTtl: Int? = null

        val peers = mutableListOf<ParsedPeer>()
        var currentPeerKey = ""
        var currentPeerEndpoint = ""
        var currentPeerAllowedIps = mutableListOf<String>()
        var currentPeerKeepalive: Int? = null

        fun savePeer() {
            if (currentPeerKey.isNotEmpty() || currentPeerEndpoint.isNotEmpty()) {
                peers.add(
                    ParsedPeer(
                        publicKey = currentPeerKey,
                        endpoint = currentPeerEndpoint,
                        allowedIps = currentPeerAllowedIps.toList(),
                        persistentKeepalive = currentPeerKeepalive
                    )
                )
            }
            currentPeerKey = ""
            currentPeerEndpoint = ""
            currentPeerAllowedIps = mutableListOf()
            currentPeerKeepalive = null
        }

        rawContent.lines().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith(";")) {
                return@forEach
            }

            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                val sec = trimmed.substring(1, trimmed.length - 1).trim().lowercase()
                if (currentSection == "peer") {
                    savePeer()
                }
                currentSection = sec
                return@forEach
            }

            val parts = trimmed.split("=", limit = 2)
            if (parts.size != 2) return@forEach
            val key = parts[0].trim().lowercase()
            val value = parts[1].trim().split("#")[0].split(";")[0].trim()

            when (currentSection) {
                "interface" -> {
                    when (key) {
                        "privatekey" -> privateKey = value
                        "address" -> {
                            value.split(",").forEach { addr ->
                                val clean = addr.trim()
                                if (clean.isNotEmpty()) addresses.add(clean)
                            }
                        }
                        "dns" -> {
                            value.split(",").forEach { dns ->
                                val clean = dns.trim()
                                if (clean.isNotEmpty()) dnsServers.add(clean)
                            }
                        }
                        "mtu" -> mtu = value.toIntOrNull() ?: 1280
                        "strategy" -> if (value.isNotEmpty()) strategy = value
                        "fakettl" -> if (value.isNotEmpty()) fakeTtl = value
                        "prejunk" -> preJunk = value.toIntOrNull()
                        "normalttl" -> normalTtl = value.toIntOrNull()
                    }
                }
                "peer" -> {
                    when (key) {
                        "publickey" -> currentPeerKey = value
                        "endpoint" -> currentPeerEndpoint = value
                        "allowedips" -> {
                            value.split(",").forEach { ip ->
                                val clean = ip.trim()
                                if (clean.isNotEmpty()) currentPeerAllowedIps.add(clean)
                            }
                        }
                        "persistentkeepalive" -> currentPeerKeepalive = value.toIntOrNull()
                    }
                }
            }
        }

        if (currentSection == "peer") {
            savePeer()
        }

        return ParsedConfig(
            iface = ParsedInterface(
                privateKey = privateKey,
                addresses = addresses,
                dnsServers = dnsServers,
                mtu = mtu,
                strategy = strategy,
                fakeTtl = fakeTtl,
                preJunk = preJunk,
                normalTtl = normalTtl
            ),
            peers = peers
        )
    }

    fun parseProfile(
        name: String,
        rawConfig: String,
        id: String? = null,
        subscriptionUrl: String? = null
    ): WgProfile {
        var effectiveName = name
        var effectiveConfig = rawConfig.trim()

        // 1. Support wireguard://, wg:// and awg:// URL schemes (standard X-UI / 3X-UI / Sing-box / Happ WireGuard links)
        if (effectiveConfig.startsWith("wireguard://", ignoreCase = true) ||
            effectiveConfig.startsWith("wg://", ignoreCase = true) ||
            effectiveConfig.startsWith("awg://", ignoreCase = true)
        ) {
            val wgParsed = parseWireGuardUrl(effectiveConfig)
            if (wgParsed != null) {
                effectiveConfig = wgParsed.first
                if (name.isBlank() || name == "Профиль из буфера" || name == "Новая конфигурация" ||
                    name.startsWith("wireguard://", ignoreCase = true) || name.startsWith("wg://", ignoreCase = true) ||
                    name.startsWith("Профиль ")
                ) {
                    if (wgParsed.second.isNotBlank()) {
                        effectiveName = wgParsed.second
                    }
                }
            }
        }

        // 2. Support vpn:// URL scheme (AmneziaWG)
        if (effectiveConfig.startsWith("vpn://", ignoreCase = true)) {
            var parsedViaNative = false
            try {
                val jsonResult = org.travonet.backend.GoBackend.wgParseVPNURL(effectiveConfig)
                if (jsonResult != null && !jsonResult.startsWith("ERROR:")) {
                    val obj = org.json.JSONObject(jsonResult)
                    val parsedName = obj.optString("name")
                    val parsedConfig = obj.optString("config")
                    if (parsedConfig.isNotBlank()) {
                        effectiveConfig = parsedConfig
                        parsedViaNative = true
                        if (name.isBlank() || name == "Профиль из буфера" || name == "Новая конфигурация" || name.startsWith("vpn://") || name.startsWith("Профиль ")) {
                            if (parsedName.isNotBlank()) {
                                effectiveName = parsedName
                            }
                        }
                    }
                }
            } catch (e: Throwable) {
                // GoBackend JNI may be absent in JVM tests or fail to load
            }

            // Fallback for raw INI Base64 payloads when native library is not available
            if (!parsedViaNative) {
                val payload = effectiveConfig.substring(6).trim().trimEnd('.', ',', '/', '?', '#', ';')
                val decoded = tryDecodeBase64(payload)
                if (decoded != null && decoded.contains("[Interface]", ignoreCase = true)) {
                    effectiveConfig = decoded
                    if (name.isBlank() || name == "Профиль из буфера" || name == "Новая конфигурация" || name.startsWith("vpn://") || name.startsWith("Профиль ")) {
                        val endpoint = decoded.lines()
                            .firstOrNull { it.trim().startsWith("endpoint", ignoreCase = true) }
                            ?.substringAfter("=")?.trim()?.substringBefore(":")
                        effectiveName = if (!endpoint.isNullOrBlank()) "AmneziaWG ($endpoint)" else "AmneziaWG"
                    }
                }
            }
        }

        val parsed = parse(effectiveConfig)
        val endpoint = parsed.peers.firstOrNull()?.endpoint ?: ""
        val address = parsed.iface.addresses.joinToString(", ")
        val allowedIps = parsed.peers.flatMap { it.allowedIps }.joinToString(", ")
        val dns = parsed.iface.dnsServers.joinToString(", ")
        val hasStrategy = !parsed.iface.strategy.isNullOrBlank()

        return WgProfile(
            id = id ?: java.util.UUID.randomUUID().toString(),
            name = effectiveName,
            rawConfig = effectiveConfig,
            endpoint = endpoint,
            address = address,
            allowedIps = allowedIps,
            dns = dns,
            mtu = parsed.iface.mtu,
            hasEmbeddedStrategy = hasStrategy,
            embeddedStrategy = parsed.iface.strategy,
            subscriptionUrl = subscriptionUrl
        )
    }

    /**
     * Parses wireguard://, wg:// and awg:// URL schemes into standard WireGuard INI config and profile name.
     * Supports both URI format (wireguard://privkey@host:port?...) and Base64 format (wireguard://base64#name).
     */
    fun parseWireGuardUrl(urlStr: String): Pair<String, String>? {
        val trimmed = urlStr.trim()
        val isWg = trimmed.startsWith("wireguard://", ignoreCase = true) ||
                trimmed.startsWith("wg://", ignoreCase = true) ||
                trimmed.startsWith("awg://", ignoreCase = true)
        if (!isWg) return null

        val prefixLen = when {
            trimmed.startsWith("wireguard://", ignoreCase = true) -> 12
            trimmed.startsWith("awg://", ignoreCase = true) -> 6
            else -> 5
        }
        val afterScheme = trimmed.substring(prefixLen).trim()
        val fragment = if (afterScheme.contains("#")) afterScheme.substringAfter("#").trim() else ""
        val withoutFragment = afterScheme.substringBefore("#").trim()

        val decodedFragmentName = if (fragment.isNotEmpty()) {
            runCatching { java.net.URLDecoder.decode(fragment, "UTF-8") }.getOrDefault(fragment)
        } else ""

        // Case 1: Base64 payload inside wireguard://<base64>
        val decodedBase64 = tryDecodeBase64(withoutFragment)
        if (decodedBase64 != null && decodedBase64.contains("[Interface]", ignoreCase = true)) {
            val name = if (decodedFragmentName.isNotBlank()) decodedFragmentName else "WireGuard"
            return Pair(decodedBase64, name)
        }

        // Case 2: URI with query params wireguard://privateKey@host:port?...
        try {
            val fakeUri = java.net.URI("http://$withoutFragment")
            val userInfo = fakeUri.userInfo ?: ""
            val host = fakeUri.host ?: ""
            val port = if (fakeUri.port > 0) fakeUri.port else 51820
            val endpoint = if (host.isNotEmpty()) "$host:$port" else ""

            fun decodeVal(v: String): String {
                return runCatching {
                    java.net.URLDecoder.decode(v.replace("+", "%2B"), "UTF-8")
                }.getOrDefault(v)
            }

            val queryMap = mutableMapOf<String, String>()
            fakeUri.rawQuery?.split("&")?.forEach { pair ->
                val eq = pair.indexOf('=')
                if (eq > 0) {
                    val k = pair.substring(0, eq).trim().lowercase()
                    val v = decodeVal(pair.substring(eq + 1).trim())
                    queryMap[k] = v
                }
            }

            val explicitPrivate = queryMap["privatekey"] ?: queryMap["private_key"]
            val explicitPublic = queryMap["publickey"] ?: queryMap["public_key"] ?: queryMap["peer"] ?: queryMap["pubkey"]

            val privateKey = explicitPrivate ?: if (explicitPublic != null || userInfo.isNotEmpty()) userInfo else ""
            val publicKey = explicitPublic ?: if (explicitPrivate != null && userInfo.isNotEmpty()) userInfo else ""
            val address = queryMap["address"] ?: queryMap["ip"] ?: "10.0.0.2/32"
            val dns = queryMap["dns"] ?: "1.1.1.1, 8.8.8.8"
            val mtu = queryMap["mtu"]?.toIntOrNull() ?: 1280
            val allowedIps = queryMap["allowedips"] ?: queryMap["allowed_ips"] ?: "0.0.0.0/0, ::/0"
            val psk = queryMap["presharedkey"] ?: queryMap["preshared_key"] ?: queryMap["psk"]
            val keepalive = queryMap["persistentkeepalive"] ?: queryMap["persistent_keepalive"] ?: queryMap["keepalive"] ?: "25"
            val reserved = queryMap["reserved"]

            val effectiveEndpoint = if (endpoint.isNotEmpty()) endpoint else queryMap["endpoint"] ?: ""

            if (privateKey.isBlank() && publicKey.isBlank()) return null

            val sb = StringBuilder()
            sb.appendLine("[Interface]")
            sb.appendLine("PrivateKey = $privateKey")
            sb.appendLine("Address = $address")
            if (dns.isNotBlank()) sb.appendLine("DNS = $dns")
            sb.appendLine("MTU = $mtu")
            if (!reserved.isNullOrBlank()) sb.appendLine("Reserved = $reserved")

            sb.appendLine("\n[Peer]")
            sb.appendLine("PublicKey = $publicKey")
            if (effectiveEndpoint.isNotBlank()) sb.appendLine("Endpoint = $effectiveEndpoint")
            sb.appendLine("AllowedIPs = $allowedIps")
            sb.appendLine("PersistentKeepalive = $keepalive")
            if (!psk.isNullOrBlank()) sb.appendLine("PresharedKey = $psk")

            for (k in AMNEZIA_KEYS) {
                val v = queryMap[k]
                if (!v.isNullOrBlank()) {
                    sb.appendLine("${k.replaceFirstChar { it.uppercase() }} = $v")
                }
            }

            val isAwg = trimmed.startsWith("awg://", ignoreCase = true) || AMNEZIA_KEYS.any { !queryMap[it].isNullOrBlank() }
            val defaultSchemeName = if (isAwg) "AmneziaWG" else "WireGuard"

            val finalName = if (decodedFragmentName.isNotBlank()) {
                decodedFragmentName
            } else if (effectiveEndpoint.isNotBlank()) {
                "$defaultSchemeName (${effectiveEndpoint.substringBefore(':')})"
            } else {
                defaultSchemeName
            }

            return Pair(sb.toString().trimEnd() + "\n", finalName)
        } catch (_: Exception) {
            return null
        }
    }

    val AMNEZIA_KEYS = setOf(
        "jc", "jmin", "jmax",
        "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4",
        "i1", "i2", "i3", "i4", "i5",
        "headerprotectionkey", "header_protection_key",
        "contentpaddingaddition", "content_padding_addition",
        "randomtrailers", "random_trailers",
        "disablecookies", "disable_cookies",
        "rekeyaftertime", "rekey_after_time",
        "rekeytimeout", "rekey_timeout",
        "rejectaftertime", "reject_after_time",
        "keepalivetimeout", "keepalive_timeout",
        "maxhandshakeattempts", "max_handshake_attempts"
    )

    /** Проверяет, содержит ли конфигурация параметры протокола AmneziaWG (включая v3.1). */
    fun isAmneziaConfig(rawConfig: String): Boolean {
        return rawConfig.lines().any { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith(";") || !trimmed.contains("=")) {
                false
            } else {
                val key = trimmed.substringBefore("=").trim().lowercase()
                AMNEZIA_KEYS.contains(key)
            }
        }
    }

    /**
     * Готовит конфиг для GoBackend.
     *
     * Если в `[Interface]` уже есть `Strategy` (или `NoEvasion`), конфиг не
     * трогаем.
     *
     * Для AmneziaWG (наличие Jc, H1, S1, HeaderProtectionKey и т.д.):
     * протокол AmneziaWG самодостаточен и содержит собственную обфускацию wire-формата.
     * Внедрение эвристик обычного WireGuard (fake_burst, pre-junk, fake TTL) ломает
     * рукопожатие с Amnezia-сервером. Поэтому для Amnezia форсируем `NoEvasion = true`.
     *
     * Иначе внедряем выбранный в UI пресет:
     *  - обычный DSL → `Strategy` + `FakeTTL`/`PreJunk`/`NormalTTL`;
     *  - пустой DSL или алиас («none», «off», «clean») → `NoEvasion = true`.
     */
    fun prepareConfigForLaunch(profile: WgProfile, fallbackStrategy: EvasionStrategy?): String {
        val parsed = parse(profile.rawConfig)
        if (!parsed.iface.strategy.isNullOrBlank()) return profile.rawConfig
        if (isNoEvasionSet(profile.rawConfig)) return profile.rawConfig

        // AmneziaWG: не внедряем внешние эвристики обхода, чтобы не ломать собственный протокол
        if (isAmneziaConfig(profile.rawConfig)) {
            return injectIntoInterface(
                profile.rawConfig,
                listOf(
                    "# Injected by TravonetWG: AmneziaWG native obfuscation active",
                    "NoEvasion = true"
                )
            )
        }

        if (fallbackStrategy == null) return profile.rawConfig

        val directives = if (DefaultStrategies.isNoEvasion(fallbackStrategy.dsl)) {
            listOf(
                "# Injected by TravonetWG: evasion disabled",
                "NoEvasion = true"
            )
        } else {
            listOf(
                "# Injected by TravonetWG Evasion Strategy: ${fallbackStrategy.name}",
                "Strategy = ${fallbackStrategy.dsl}",
                "FakeTTL = ${fallbackStrategy.fakeTtl}",
                "PreJunk = ${fallbackStrategy.preJunk}",
                "NormalTTL = ${fallbackStrategy.normalTtl}"
            )
        }

        return injectIntoInterface(profile.rawConfig, directives)
    }

    /** `NoEvasion = true` (а также `no_evasion`/`disable_evasion`) в исходном конфиге. */
    private fun isNoEvasionSet(rawConfig: String): Boolean {
        val keys = setOf("noevasion", "no_evasion", "disable_evasion")
        val truthy = setOf("1", "true", "yes", "on")
        rawConfig.lineSequence().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.startsWith("#") || trimmed.startsWith(";")) return@forEach
            val parts = trimmed.split("=", limit = 2)
            if (parts.size != 2) return@forEach
            if (parts[0].trim().lowercase() !in keys) return@forEach
            val value = parts[1].substringBefore('#').substringBefore(';').trim().lowercase()
            if (value in truthy) return true
        }
        return false
    }

    /** Вставляет строки сразу после заголовка `[Interface]`. */
    private fun injectIntoInterface(rawConfig: String, directives: List<String>): String {
        val sb = StringBuilder()
        var injected = false
        rawConfig.lines().forEach { line ->
            sb.appendLine(line)
            if (!injected && line.trim().equals("[Interface]", ignoreCase = true)) {
                directives.forEach { sb.appendLine(it) }
                injected = true
            }
        }
        // Без секции [Interface] это не .conf-файл: оставляем как есть.
        return if (injected) sb.toString() else rawConfig
    }

    /**
     * Гарантирует наличие PersistentKeepalive = 15 для каждого [Peer].
     * Без keepalive мобильные операторы и роутеры сбрасывают UDP NAT-сессию
     * через 20-30 секунд простоя, из-за чего входящий и фоновый трафик перестаёт поступать.
     */
    fun ensurePersistentKeepalive(rawConfig: String, defaultInterval: Int = 15): String {
        val lines = rawConfig.lines()
        val result = mutableListOf<String>()
        var inPeer = false
        var peerHasKeepalive = false

        fun finalizePeer() {
            if (inPeer && !peerHasKeepalive) {
                result.add("PersistentKeepalive = $defaultInterval")
            }
        }

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                val sec = trimmed.substring(1, trimmed.length - 1).trim().lowercase()
                finalizePeer()
                inPeer = (sec == "peer")
                peerHasKeepalive = false
                result.add(line)
                continue
            }

            if (inPeer && trimmed.contains("=")) {
                val key = trimmed.substringBefore('=').trim().lowercase()
                val value = trimmed.substringAfter('=').substringBefore('#').substringBefore(';').trim().toIntOrNull()
                if (key == "persistentkeepalive") {
                    if (value != null && value > 0) {
                        peerHasKeepalive = true
                        result.add(line)
                    } else {
                        peerHasKeepalive = true
                        result.add("PersistentKeepalive = $defaultInterval")
                    }
                    continue
                }
            }

            result.add(line)
        }

        finalizePeer()
        return result.joinToString("\n")
    }

    /**
     * Преобразует доменные имена в Endpoint директивах пиров в IPv4-адреса.
     *
     * Как только Android VpnService выполняет establish(), весь системный DNS
     * направляется в TUN-интерфейс, который ещё не подключен. Если эндпоинт
     * задан доменом, Go-ядро не может его разрешить. Кроме того, userspace-обход
     * DPI в ядре работает только для IPv4; выбор IPv6 на сотовой сети отключает
     * обход.
     */
    fun resolveConfigEndpoints(rawConfig: String): String {
        val lines = rawConfig.lines()
        val sb = StringBuilder()
        for (line in lines) {
            val trimmed = line.trim()
            if (!trimmed.startsWith("#") && !trimmed.startsWith(";") && trimmed.contains("=")) {
                val parts = trimmed.split("=", limit = 2)
                if (parts[0].trim().equals("endpoint", ignoreCase = true)) {
                    val originalEndpoint = parts[1].substringBefore('#').substringBefore(';').trim()
                    val resolved = resolveEndpointToIpv4(originalEndpoint)
                    if (resolved != originalEndpoint) {
                        sb.appendLine("${parts[0].trim()} = $resolved")
                        continue
                    }
                }
            }
            sb.appendLine(line)
        }
        return sb.toString().trimEnd() + "\n"
    }

    fun resolveEndpointToIpv4(endpoint: String): String {
        if (endpoint.isBlank()) return endpoint
        val lastColon = endpoint.lastIndexOf(':')
        if (lastColon <= 0) return endpoint
        val host = endpoint.substring(0, lastColon).removePrefix("[").removeSuffix("]").trim()
        val port = endpoint.substring(lastColon + 1).trim()

        val ipv4Parts = host.split('.')
        if (ipv4Parts.size == 4 && ipv4Parts.all { it.toIntOrNull() in 0..255 }) {
            return endpoint
        }

        if (host.contains(':')) {
            return endpoint
        }

        return try {
            val future = java.util.concurrent.CompletableFuture.supplyAsync {
                java.net.InetAddress.getAllByName(host)
            }
            val addrs = future.get(3500, java.util.concurrent.TimeUnit.MILLISECONDS)
            val ipv4 = addrs.firstOrNull { it is java.net.Inet4Address }
            if (ipv4 != null) {
                "${ipv4.hostAddress}:$port"
            } else {
                endpoint
            }
        } catch (_: Exception) {
            endpoint
        }
    }

    private fun tryDecodeBase64(input: String): String? {
        val sanitized = input.replace("\r", "").replace("\n", "").replace(" ", "").trim()
        if (sanitized.isEmpty()) return null

        val decoders = listOfNotNull(
            runCatching { java.util.Base64.getDecoder() }.getOrNull(),
            runCatching { java.util.Base64.getUrlDecoder() }.getOrNull()
        )
        for (decoder in decoders) {
            try {
                val bytes = decoder.decode(sanitized)
                if (bytes != null && bytes.isNotEmpty()) {
                    return String(bytes, java.nio.charset.StandardCharsets.UTF_8)
                }
            } catch (_: Exception) {}

            val rem = sanitized.length % 4
            if (rem != 0) {
                try {
                    val padded = sanitized + "=".repeat(4 - rem)
                    val bytes = decoder.decode(padded)
                    if (bytes != null && bytes.isNotEmpty()) {
                        return String(bytes, java.nio.charset.StandardCharsets.UTF_8)
                    }
                } catch (_: Exception) {}
            }
        }
        return null
    }
}
