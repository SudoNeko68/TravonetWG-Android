package com.travonet.wireguard.parser

import com.travonet.wireguard.model.WgProfile
import org.json.JSONObject
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.UUID

object ProxyLinkParser {

    fun isProxyLink(input: String): Boolean {
        val s = input.trim().lowercase()
        return s.startsWith("vless://") ||
                s.startsWith("vmess://") ||
                s.startsWith("trojan://") ||
                s.startsWith("ss://") ||
                s.startsWith("tuic://") ||
                s.startsWith("hysteria2://") ||
                s.startsWith("hy2://") ||
                s.startsWith("shadowtls://") ||
                s.startsWith("freeturn://") ||
                (s.contains("-peer") && (s.contains("-link") || s.contains("-provider"))) ||
                s.startsWith("wireguard://") ||
                s.startsWith("wg://") ||
                s.startsWith("vpn://")
    }

    fun parse(
        rawUri: String,
        fallbackName: String? = null,
        subUrl: String? = null,
        id: String? = null
    ): WgProfile? {
        val trimmed = rawUri.trim()
        val s = trimmed.lowercase()

        val profile = when {
            s.startsWith("vless://") -> parseVless(trimmed, fallbackName, subUrl, id)
            s.startsWith("vmess://") -> parseVmess(trimmed, fallbackName, subUrl, id)
            s.startsWith("trojan://") -> parseTrojan(trimmed, fallbackName, subUrl, id)
            s.startsWith("ss://") -> parseShadowsocks(trimmed, fallbackName, subUrl, id)
            s.startsWith("tuic://") -> parseTuic(trimmed, fallbackName, subUrl, id)
            s.startsWith("hysteria2://") || s.startsWith("hy2://") -> parseHysteria2(trimmed, fallbackName, subUrl, id)
            s.startsWith("shadowtls://") -> parseShadowTls(trimmed, fallbackName, subUrl, id)
            s.startsWith("freeturn://") || (s.contains("-peer") && (s.contains("-link") || s.contains("-provider"))) -> {
                parseFreeTurn(trimmed, fallbackName, subUrl, id)
            }
            s.startsWith("wireguard://") || s.startsWith("wg://") || s.startsWith("vpn://") -> {
                return WgConfigParser.parseProfile(fallbackName ?: "WireGuard", trimmed, id, subUrl)
            }
            else -> null
        } ?: return null

        val routing = com.travonet.wireguard.core.CoreRouter.route(trimmed)
        val synthesized = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(trimmed, routing.targetCore)
        return profile.copy(rawConfig = synthesized)
    }

    private fun decodeFragment(fragment: String): String {
        return try {
            URLDecoder.decode(fragment.replace("+", "%2B"), StandardCharsets.UTF_8.name()).trim()
        } catch (_: Exception) {
            fragment.trim()
        }
    }

    private fun tryDecodeBase64(input: String): String? {
        val sanitized = input.replace("\r", "").replace("\n", "").replace(" ", "").trim()
        if (sanitized.isEmpty()) return null

        val decoders = listOfNotNull(
            runCatching { Base64.getDecoder() }.getOrNull(),
            runCatching { Base64.getUrlDecoder() }.getOrNull()
        )
        for (decoder in decoders) {
            try {
                val bytes = decoder.decode(sanitized)
                if (bytes != null && bytes.isNotEmpty()) {
                    return String(bytes, StandardCharsets.UTF_8)
                }
            } catch (_: Exception) {}

            val rem = sanitized.length % 4
            if (rem != 0) {
                try {
                    val padded = sanitized + "=".repeat(4 - rem)
                    val bytes = decoder.decode(padded)
                    if (bytes != null && bytes.isNotEmpty()) {
                        return String(bytes, StandardCharsets.UTF_8)
                    }
                } catch (_: Exception) {}
            }
        }
        return null
    }

    // 1. VLESS: vless://uuid@host:port?security=reality&flow=xtls-rprx-vision&type=tcp...#name
    private fun parseVless(
        uri: String,
        fallbackName: String?,
        subUrl: String?,
        id: String?
    ): WgProfile? {
        val fragment = if (uri.contains("#")) uri.substringAfter("#") else ""
        val withoutFrag = uri.substringBefore("#").removePrefix("vless://").removePrefix("VLESS://")

        val atIdx = withoutFrag.indexOf('@')
        if (atIdx <= 0) return null
        val uuid = withoutFrag.substring(0, atIdx).trim()
        val afterAt = withoutFrag.substring(atIdx + 1)

        val qIdx = afterAt.indexOf('?')
        val hostPort = if (qIdx >= 0) afterAt.substring(0, qIdx).trim() else afterAt.trim()
        val query = if (qIdx >= 0) afterAt.substring(qIdx + 1).trim() else ""

        val queryMap = parseQuery(query)
        val security = queryMap["security"] ?: "none"
        val type = queryMap["type"] ?: "tcp"
        val flow = queryMap["flow"]

        val name = when {
            fragment.isNotBlank() -> decodeFragment(fragment)
            !fallbackName.isNullOrBlank() -> fallbackName
            else -> "VLESS ($hostPort)"
        }

        val infoParts = mutableListOf("VLESS", security, type)
        if (!flow.isNullOrBlank()) infoParts.add(flow)

        return WgProfile(
            id = id ?: UUID.randomUUID().toString(),
            name = name,
            rawConfig = uri,
            endpoint = hostPort,
            address = infoParts.joinToString(" • "),
            allowedIps = "0.0.0.0/0, ::/0",
            subscriptionUrl = subUrl
        )
    }

    // 2. VMess: vmess://base64-json
    private fun parseVmess(
        uri: String,
        fallbackName: String?,
        subUrl: String?,
        id: String?
    ): WgProfile? {
        val payload = uri.removePrefix("vmess://").removePrefix("VMESS://").substringBefore("#")
        val fragment = if (uri.contains("#")) uri.substringAfter("#") else ""
        val decoded = tryDecodeBase64(payload) ?: return null

        return try {
            val json = JSONObject(decoded)
            val ps = json.optString("ps", "")
            val add = json.optString("add", "")
            val port = json.opt("port")?.toString() ?: "443"
            val net = json.optString("net", "tcp")
            val tls = json.optString("tls", "none")
            val hostPort = if (add.isNotBlank()) "$add:$port" else ""

            val name = when {
                ps.isNotBlank() -> ps
                fragment.isNotBlank() -> decodeFragment(fragment)
                !fallbackName.isNullOrBlank() -> fallbackName
                hostPort.isNotBlank() -> "VMess ($hostPort)"
                else -> "VMess"
            }

            WgProfile(
                id = id ?: UUID.randomUUID().toString(),
                name = name,
                rawConfig = uri,
                endpoint = hostPort,
                address = "VMess • $net • $tls",
                allowedIps = "0.0.0.0/0, ::/0",
                subscriptionUrl = subUrl
            )
        } catch (_: Exception) {
            null
        }
    }

    // 3. Trojan: trojan://password@host:port?security=tls...#name
    private fun parseTrojan(
        uri: String,
        fallbackName: String?,
        subUrl: String?,
        id: String?
    ): WgProfile? {
        val fragment = if (uri.contains("#")) uri.substringAfter("#") else ""
        val withoutFrag = uri.substringBefore("#").removePrefix("trojan://").removePrefix("TROJAN://")

        val atIdx = withoutFrag.indexOf('@')
        if (atIdx <= 0) return null
        val afterAt = withoutFrag.substring(atIdx + 1)
        val qIdx = afterAt.indexOf('?')
        val hostPort = if (qIdx >= 0) afterAt.substring(0, qIdx).trim() else afterAt.trim()

        val name = when {
            fragment.isNotBlank() -> decodeFragment(fragment)
            !fallbackName.isNullOrBlank() -> fallbackName
            else -> "Trojan ($hostPort)"
        }

        return WgProfile(
            id = id ?: UUID.randomUUID().toString(),
            name = name,
            rawConfig = uri,
            endpoint = hostPort,
            address = "Trojan • TLS",
            allowedIps = "0.0.0.0/0, ::/0",
            subscriptionUrl = subUrl
        )
    }

    // 4. Shadowsocks: ss://base64@host:port#name or ss://base64#name
    private fun parseShadowsocks(
        uri: String,
        fallbackName: String?,
        subUrl: String?,
        id: String?
    ): WgProfile? {
        val fragment = if (uri.contains("#")) uri.substringAfter("#") else ""
        val withoutFrag = uri.substringBefore("#").removePrefix("ss://").removePrefix("SS://")

        var hostPort = ""
        val atIdx = withoutFrag.indexOf('@')
        if (atIdx >= 0) {
            hostPort = withoutFrag.substring(atIdx + 1).substringBefore('?').substringBefore('/')
        } else {
            val decoded = tryDecodeBase64(withoutFrag)
            if (decoded != null && decoded.contains("@")) {
                hostPort = decoded.substringAfter("@").substringBefore('?').substringBefore('/')
            }
        }

        val name = when {
            fragment.isNotBlank() -> decodeFragment(fragment)
            !fallbackName.isNullOrBlank() -> fallbackName
            hostPort.isNotBlank() -> "Shadowsocks ($hostPort)"
            else -> "Shadowsocks"
        }

        return WgProfile(
            id = id ?: UUID.randomUUID().toString(),
            name = name,
            rawConfig = uri,
            endpoint = hostPort,
            address = "Shadowsocks",
            allowedIps = "0.0.0.0/0, ::/0",
            subscriptionUrl = subUrl
        )
    }

    // 5. TUIC: tuic://uuid:password@host:port?congestion_control=bbr...#name
    private fun parseTuic(
        uri: String,
        fallbackName: String?,
        subUrl: String?,
        id: String?
    ): WgProfile? {
        val fragment = if (uri.contains("#")) uri.substringAfter("#") else ""
        val withoutFrag = uri.substringBefore("#").removePrefix("tuic://").removePrefix("TUIC://")

        val atIdx = withoutFrag.indexOf('@')
        if (atIdx <= 0) return null
        val afterAt = withoutFrag.substring(atIdx + 1)
        val qIdx = afterAt.indexOf('?')
        val hostPort = if (qIdx >= 0) afterAt.substring(0, qIdx).trim() else afterAt.trim()
        val query = if (qIdx >= 0) afterAt.substring(qIdx + 1).trim() else ""
        val queryMap = parseQuery(query)
        val cc = queryMap["congestion_control"] ?: "bbr"

        val name = when {
            fragment.isNotBlank() -> decodeFragment(fragment)
            !fallbackName.isNullOrBlank() -> fallbackName
            else -> "TUIC ($hostPort)"
        }

        return WgProfile(
            id = id ?: UUID.randomUUID().toString(),
            name = name,
            rawConfig = uri,
            endpoint = hostPort,
            address = "TUIC v5 • QUIC • $cc",
            allowedIps = "0.0.0.0/0, ::/0",
            subscriptionUrl = subUrl
        )
    }

    // 6. Hysteria 2: hysteria2://password@host:port?sni=...#name or hy2://...
    private fun parseHysteria2(
        uri: String,
        fallbackName: String?,
        subUrl: String?,
        id: String?
    ): WgProfile? {
        val fragment = if (uri.contains("#")) uri.substringAfter("#") else ""
        val withoutFrag = uri.substringBefore("#")
            .removePrefix("hysteria2://").removePrefix("HYSTERIA2://")
            .removePrefix("hy2://").removePrefix("HY2://")

        val atIdx = withoutFrag.lastIndexOf('@')
        val afterAt = if (atIdx >= 0) withoutFrag.substring(atIdx + 1) else withoutFrag
        val hostPort = afterAt.substringBefore('?').substringBefore('/').trim()

        val name = when {
            fragment.isNotBlank() -> decodeFragment(fragment)
            !fallbackName.isNullOrBlank() -> fallbackName
            else -> "Hysteria 2 ($hostPort)"
        }

        return WgProfile(
            id = id ?: UUID.randomUUID().toString(),
            name = name,
            rawConfig = uri,
            endpoint = hostPort,
            address = "Hysteria 2 • QUIC",
            allowedIps = "0.0.0.0/0, ::/0",
            subscriptionUrl = subUrl
        )
    }

    // 7. ShadowTLS: shadowtls://host:port?password=...#name
    private fun parseShadowTls(
        uri: String,
        fallbackName: String?,
        subUrl: String?,
        id: String?
    ): WgProfile? {
        val fragment = if (uri.contains("#")) uri.substringAfter("#") else ""
        val withoutFrag = uri.substringBefore("#")
            .removePrefix("shadowtls://").removePrefix("SHADOWTLS://")

        val afterAt = if (withoutFrag.contains('@')) withoutFrag.substringAfter('@') else withoutFrag
        val hostPort = afterAt.substringBefore('?').substringBefore('/')

        val name = when {
            fragment.isNotBlank() -> decodeFragment(fragment)
            !fallbackName.isNullOrBlank() -> fallbackName
            else -> "ShadowTLS ($hostPort)"
        }

        return WgProfile(
            id = id ?: UUID.randomUUID().toString(),
            name = name,
            rawConfig = uri,
            endpoint = hostPort,
            address = "ShadowTLS",
            allowedIps = "0.0.0.0/0, ::/0",
            subscriptionUrl = subUrl
        )
    }

    // 8. FreeTURN: freeturn://<base64url(json)> or CLI flags
    fun extractEmbeddedWgConfig(rawConfig: String): String? {
        val trimmed = rawConfig.trim()
        if (trimmed.contains("[Interface]", ignoreCase = true) && trimmed.contains("[Peer]", ignoreCase = true)) {
            return trimmed
        }
        if (trimmed.startsWith("freeturn://", ignoreCase = true)) {
            val b64 = trimmed.removePrefix("freeturn://").removePrefix("FREETURN://").substringBefore(" ").trim()
            val decoded = tryDecodeBase64(b64)
            if (decoded != null && decoded.startsWith("{")) {
                try {
                    val obj = JSONObject(decoded)
                    val wg = obj.optString("wg", "")
                    if (wg.isNotBlank()) return wg
                } catch (_: Exception) {}
            }
        }
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                val obj = JSONObject(trimmed)
                val wg = obj.optString("wg", "")
                if (wg.isNotBlank()) return wg
                val tunnel = obj.optJSONObject("tunnel")
                val tConfig = tunnel?.optString("config", "")
                if (!tConfig.isNullOrBlank()) return tConfig
            } catch (_: Exception) {}
        }
        return null
    }

    private fun parseFreeTurn(
        uri: String,
        fallbackName: String?,
        subUrl: String?,
        id: String?
    ): WgProfile? {
        var name = fallbackName ?: "FreeTURN"
        var endpoint = ""
        var address = "FreeTURN • VK"
        var dns = ""
        var mtu = 1280

        val embeddedWg = extractEmbeddedWgConfig(uri)
        if (embeddedWg != null) {
            try {
                val parsed = WgConfigParser.parse(embeddedWg)
                if (parsed.iface.addresses.isNotEmpty()) {
                    address = parsed.iface.addresses.joinToString(", ")
                }
                if (parsed.iface.dnsServers.isNotEmpty()) {
                    dns = parsed.iface.dnsServers.joinToString(", ")
                }
                if (parsed.iface.mtu > 0) {
                    mtu = parsed.iface.mtu
                }
            } catch (_: Exception) {}
        }

        if (uri.startsWith("freeturn://", ignoreCase = true)) {
            val b64 = uri.substring(11).substringBefore(" ").trim()
            val decoded = tryDecodeBase64(b64)
            if (decoded != null && decoded.startsWith("{")) {
                try {
                    val obj = JSONObject(decoded)
                    val jsonName = obj.optString("name", "")
                    val peer = obj.optString("peer", "")
                    if (peer.isNotBlank()) endpoint = peer
                    if (jsonName.isNotBlank()) {
                        name = jsonName
                    } else if (peer.isNotBlank()) {
                        name = "FreeTURN ($peer)"
                    }
                } catch (_: Exception) {}
            }
        } else if (uri.contains("-peer", ignoreCase = true)) {
            val peerMatch = Regex("""-peer\s+([^\s]+)""").find(uri)
            if (peerMatch != null) {
                endpoint = peerMatch.groupValues[1]
                name = fallbackName ?: "FreeTURN ($endpoint)"
            }
        }

        return WgProfile(
            id = id ?: UUID.randomUUID().toString(),
            name = name,
            rawConfig = uri,
            endpoint = endpoint,
            address = address,
            allowedIps = "0.0.0.0/0, ::/0",
            dns = dns,
            mtu = mtu,
            subscriptionUrl = subUrl
        )
    }

    private fun parseQuery(query: String): Map<String, String> {
        if (query.isBlank()) return emptyMap()
        val map = mutableMapOf<String, String>()
        query.split('&').forEach { pair ->
            val eq = pair.indexOf('=')
            if (eq > 0) {
                val k = pair.substring(0, eq).trim().lowercase()
                val rawVal = pair.substring(eq + 1).trim()
                val v = try {
                    URLDecoder.decode(rawVal.replace("+", "%2B"), StandardCharsets.UTF_8.name())
                } catch (_: Exception) {
                    rawVal
                }
                map[k] = v
            }
        }
        return map
    }
}
