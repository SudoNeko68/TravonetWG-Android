package com.travonet.wireguard.core

object CoreRouter {

    fun getEffectiveCore(
        protocol: SupportedProtocol,
        customDelegations: Map<String, String>? = null
    ): CoreType {
        val customCoreId = customDelegations?.get(protocol.id)
        if (!customCoreId.isNullOrBlank()) {
            val matchedCore = protocol.compatibleCores.firstOrNull { it.id == customCoreId }
            if (matchedCore != null) return matchedCore
        }
        return protocol.defaultCore
    }

    fun getRules(customDelegations: Map<String, String>? = null): List<ProtocolRoutingRule> {
        return SupportedProtocol.values().map { sp ->
            val target = getEffectiveCore(sp, customDelegations)
            ProtocolRoutingRule(
                protocol = sp.displayName,
                targetCore = target,
                description = sp.description,
                exampleUri = sp.exampleUri,
                isPreferred = target == sp.defaultCore
            )
        }
    }

    val RULES: List<ProtocolRoutingRule>
        get() = getRules(null)

    fun route(
        rawInput: String,
        customDelegations: Map<String, String>? = null
    ): RoutingResult {
        val trimmed = rawInput.trim()

        val protocol = when {
            // 0. JSON Configs (FreeTURN vs Sing-Box vs Xray)
            trimmed.startsWith("{") && trimmed.endsWith("}") -> {
                when {
                    isFreeTurnJson(trimmed) -> SupportedProtocol.FREETURN
                    isXrayJson(trimmed) -> detectXrayProtocol(trimmed)
                    isSingBoxJson(trimmed) -> detectSingBoxProtocol(trimmed)
                    else -> detectSingBoxProtocol(trimmed)
                }
            }

            // 1. AmneziaWG
            trimmed.startsWith("vpn://", ignoreCase = true) || isAmneziaIni(trimmed) -> {
                SupportedProtocol.AMNEZIA_WG
            }

            // 2. WireGuard
            trimmed.startsWith("wireguard://", ignoreCase = true) ||
            trimmed.startsWith("wg://", ignoreCase = true) ||
            trimmed.contains("[Interface]", ignoreCase = true) -> {
                SupportedProtocol.WIREGUARD
            }

            // 3. WARP
            trimmed.startsWith("warp://", ignoreCase = true) -> {
                SupportedProtocol.WARP
            }

            // 4. VLESS
            trimmed.startsWith("vless://", ignoreCase = true) -> {
                SupportedProtocol.VLESS
            }

            // 5. VMess
            trimmed.startsWith("vmess://", ignoreCase = true) -> {
                SupportedProtocol.VMESS
            }

            // 6. Trojan
            trimmed.startsWith("trojan://", ignoreCase = true) -> {
                SupportedProtocol.TROJAN
            }

            // 7. Shadowsocks
            trimmed.startsWith("ss://", ignoreCase = true) -> {
                SupportedProtocol.SHADOWSOCKS
            }

            // 8. TUIC
            trimmed.startsWith("tuic://", ignoreCase = true) -> {
                SupportedProtocol.TUIC
            }

            // 9. Hysteria 2
            trimmed.startsWith("hysteria2://", ignoreCase = true) ||
            trimmed.startsWith("hy2://", ignoreCase = true) -> {
                SupportedProtocol.HYSTERIA2
            }

            // 10. ShadowTLS
            trimmed.startsWith("shadowtls://", ignoreCase = true) -> {
                SupportedProtocol.SHADOWTLS
            }

            // 11. FreeTURN
            trimmed.startsWith("freeturn://", ignoreCase = true) || isFreeTurnCli(trimmed) -> {
                SupportedProtocol.FREETURN
            }

            else -> SupportedProtocol.WIREGUARD
        }

        val targetCore = getEffectiveCore(protocol, customDelegations)
        val rule = ProtocolRoutingRule(
            protocol = protocol.displayName,
            targetCore = targetCore,
            description = protocol.description,
            exampleUri = protocol.exampleUri,
            isPreferred = targetCore == protocol.defaultCore
        )

        val explanation = if (targetCore != protocol.defaultCore) {
            "Протокол ${protocol.displayName} перенаправлен в ядро ${targetCore.title} согласно пользовательской настройке делегирования."
        } else {
            "Протокол ${protocol.displayName} обрабатывается ядром ${targetCore.title}."
        }

        return RoutingResult(
            targetCore = targetCore,
            detectedProtocol = protocol.displayName,
            rule = rule,
            explanation = explanation
        )
    }

    private fun isAmneziaIni(iniText: String): Boolean {
        if (!iniText.contains("[Interface]", ignoreCase = true)) return false
        val keys = listOf("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4", "i1", "i2")
        return iniText.lines().any { line ->
            val trimmed = line.trim()
            if (trimmed.startsWith("#") || trimmed.startsWith(";") || !trimmed.contains("=")) return@any false
            val k = trimmed.substringBefore("=").trim().lowercase()
            keys.contains(k)
        }
    }

    private fun isXrayJson(json: String): Boolean {
        val lower = json.lowercase()
        if (lower.contains("\"streamsettings\"") || lower.contains("\"routing\"") || lower.contains("\"loglevel\"")) {
            return true
        }
        try {
            val root = org.json.JSONObject(json)
            val outbounds = root.optJSONArray("outbounds")
            if (outbounds != null) {
                for (i in 0 until outbounds.length()) {
                    val ob = outbounds.optJSONObject(i) ?: continue
                    if (ob.has("protocol") && !ob.has("type")) {
                        return true
                    }
                }
            }
        } catch (_: Exception) {}
        return false
    }

    private fun isSingBoxJson(json: String): Boolean {
        if (isXrayJson(json)) return false
        val lower = json.lowercase()
        if (lower.contains("\"experimental\"") ||
            lower.contains("\"clash_api\"") ||
            lower.contains("\"hysteria2\"") ||
            lower.contains("\"hysteria\"") ||
            lower.contains("\"tuic\"") ||
            lower.contains("\"shadowtls\"") ||
            (lower.contains("\"route\"") && !lower.contains("\"routing\""))) {
            return true
        }
        try {
            val root = org.json.JSONObject(json)
            val outbounds = root.optJSONArray("outbounds")
            if (outbounds != null) {
                for (i in 0 until outbounds.length()) {
                    val ob = outbounds.optJSONObject(i) ?: continue
                    if (ob.has("type")) {
                        return true
                    }
                }
            }
        } catch (_: Exception) {}
        return false
    }

    private fun detectSingBoxProtocol(json: String): SupportedProtocol {
        try {
            val root = org.json.JSONObject(json)
            val outbounds = root.optJSONArray("outbounds")
            if (outbounds != null) {
                for (i in 0 until outbounds.length()) {
                    val ob = outbounds.optJSONObject(i) ?: continue
                    val type = ob.optString("type", ob.optString("protocol", "")).lowercase()
                    if (type == "direct" || type == "freedom" || type == "block" || type == "blackhole" || type == "dns") {
                        continue
                    }
                    when (type) {
                        "vless" -> return SupportedProtocol.VLESS
                        "vmess" -> return SupportedProtocol.VMESS
                        "trojan" -> return SupportedProtocol.TROJAN
                        "shadowsocks", "ss" -> return SupportedProtocol.SHADOWSOCKS
                        "tuic" -> return SupportedProtocol.TUIC
                        "hysteria2", "hysteria", "hy2" -> return SupportedProtocol.HYSTERIA2
                        "shadowtls" -> return SupportedProtocol.SHADOWTLS
                        "wireguard", "wg" -> return SupportedProtocol.WIREGUARD
                    }
                }
            }
        } catch (_: Exception) {}

        val lower = json.lowercase()
        return when {
            lower.contains("\"vless\"") -> SupportedProtocol.VLESS
            lower.contains("\"vmess\"") -> SupportedProtocol.VMESS
            lower.contains("\"trojan\"") -> SupportedProtocol.TROJAN
            lower.contains("\"shadowsocks\"") || lower.contains("\"type\":\"ss\"") -> SupportedProtocol.SHADOWSOCKS
            lower.contains("\"tuic\"") -> SupportedProtocol.TUIC
            lower.contains("\"hysteria2\"") || lower.contains("\"hysteria\"") || lower.contains("\"hy2\"") -> SupportedProtocol.HYSTERIA2
            lower.contains("\"shadowtls\"") -> SupportedProtocol.SHADOWTLS
            lower.contains("\"wireguard\"") -> SupportedProtocol.WIREGUARD
            else -> SupportedProtocol.VLESS
        }
    }

    private fun detectXrayProtocol(json: String): SupportedProtocol {
        try {
            val root = org.json.JSONObject(json)
            val outbounds = root.optJSONArray("outbounds")
            if (outbounds != null) {
                for (i in 0 until outbounds.length()) {
                    val ob = outbounds.optJSONObject(i) ?: continue
                    val proto = ob.optString("protocol", ob.optString("type", "")).lowercase()
                    if (proto == "freedom" || proto == "direct" || proto == "blackhole" || proto == "block" || proto == "dns") {
                        continue
                    }
                    when (proto) {
                        "vless" -> return SupportedProtocol.VLESS
                        "vmess" -> return SupportedProtocol.VMESS
                        "trojan" -> return SupportedProtocol.TROJAN
                        "shadowsocks", "ss" -> return SupportedProtocol.SHADOWSOCKS
                        "wireguard", "wg" -> return SupportedProtocol.WIREGUARD
                    }
                }
            }
        } catch (_: Exception) {}

        val lower = json.lowercase()
        return when {
            lower.contains("\"vless\"") -> SupportedProtocol.VLESS
            lower.contains("\"vmess\"") -> SupportedProtocol.VMESS
            lower.contains("\"trojan\"") -> SupportedProtocol.TROJAN
            lower.contains("\"shadowsocks\"") -> SupportedProtocol.SHADOWSOCKS
            else -> SupportedProtocol.VLESS
        }
    }

    private fun isFreeTurnCli(cliText: String): Boolean {
        return (cliText.contains("-peer", ignoreCase = true) && (cliText.contains("-link", ignoreCase = true) || cliText.contains("-provider", ignoreCase = true))) ||
                cliText.contains("-links http", ignoreCase = true)
    }

    private fun isFreeTurnJson(json: String): Boolean {
        return (json.contains("\"peer\"") && (json.contains("\"provider\"") || json.contains("\"vk\""))) ||
                json.contains("\"manualCaptcha\"") ||
                (json.contains("\"vk\"") && json.contains("\"links\""))
    }
}
