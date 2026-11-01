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
     * Готовит конфиг для GoBackend.
     *
     * Если в `[Interface]` уже есть `Strategy` (или `NoEvasion`), конфиг не
     * трогаем. Иначе внедряем выбранный в UI пресет:
     *  - обычный DSL → `Strategy` + `FakeTTL`/`PreJunk`/`NormalTTL`;
     *  - пустой DSL или алиас («none», «off», «clean») → `NoEvasion = true`.
     *
     * Раньше пустой DSL означал «ничего не внедрять», и ядро включало свою
     * стратегию по умолчанию — то есть «Чистый WireGuard» на деле не был чистым.
     */
    fun prepareConfigForLaunch(profile: WgProfile, fallbackStrategy: EvasionStrategy?): String {
        val parsed = parse(profile.rawConfig)
        if (!parsed.iface.strategy.isNullOrBlank()) return profile.rawConfig
        if (isNoEvasionSet(profile.rawConfig)) return profile.rawConfig
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
