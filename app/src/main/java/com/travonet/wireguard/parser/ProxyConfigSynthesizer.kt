package com.travonet.wireguard.parser

import com.travonet.wireguard.core.CoreType
import com.travonet.wireguard.model.DnsMode
import com.travonet.wireguard.model.TunnelMode
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

object ProxyConfigSynthesizer {

    fun synthesize(
        rawConfig: String,
        targetCore: CoreType,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        val trimmed = rawConfig.trim()
        if (targetCore == CoreType.FREETURN) {
            return buildFreeTurn(trimmed, mode, socksListen)
        }
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            return ensureInbound(trimmed, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
        }

        val lower = trimmed.lowercase()
        return when {
            lower.startsWith("vless://") -> buildVless(trimmed, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
            lower.startsWith("vmess://") -> buildVmess(trimmed, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
            lower.startsWith("trojan://") -> buildTrojan(trimmed, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
            lower.startsWith("ss://") -> buildShadowsocks(trimmed, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
            lower.startsWith("tuic://") -> buildTuic(trimmed, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
            lower.startsWith("hysteria2://") || lower.startsWith("hy2://") -> buildHysteria2(trimmed, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
            lower.startsWith("shadowtls://") -> buildShadowTls(trimmed, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
            else -> buildGenericProxy(trimmed, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
        }
    }

    private fun ensureInbound(
        jsonStr: String,
        targetCore: CoreType,
        mode: TunnelMode,
        socksListen: String,
        dohUrl: String = "",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        return try {
            val root = JSONObject(jsonStr)
            val inbounds = root.optJSONArray("inbounds") ?: JSONArray()
            val newInbounds = JSONArray()
            val requiredType = if (mode == TunnelMode.SOCKS5) "socks" else "tun"
            val forbiddenType = if (mode == TunnelMode.SOCKS5) "tun" else null
            var hasRequired = false

            for (i in 0 until inbounds.length()) {
                val inObj = inbounds.optJSONObject(i) ?: continue
                val type = inObj.optString("type", inObj.optString("protocol", "")).lowercase()
                if (forbiddenType != null && type == forbiddenType) {
                    continue
                }
                if (type == requiredType) {
                    hasRequired = true
                    if (type == "tun") {
                        inObj.put("stack", "gvisor")
                        inObj.put("mtu", 1420)
                        inObj.put("auto_route", false)
                        inObj.remove("sniff")
                    }
                }
                newInbounds.put(inObj)
            }

            if (!hasRequired) {
                if (targetCore == CoreType.XRAY) {
                    val xrayIn = createXrayInbound(mode, socksListen).getJSONObject(0)
                    newInbounds.put(0, xrayIn)
                } else {
                    newInbounds.put(0, createSingboxInbound(mode, socksListen))
                }
            }
            root.put("inbounds", newInbounds)

            if (targetCore == CoreType.SINGBOX) {
                // 1. Remove deprecated special outbounds (e.g. type: "dns")
                val outbounds = root.optJSONArray("outbounds")
                if (outbounds != null) {
                    val cleanOutbounds = JSONArray()
                    for (i in 0 until outbounds.length()) {
                        val outObj = outbounds.optJSONObject(i) ?: continue
                        val outType = outObj.optString("type").lowercase()
                        if (outType == "dns") {
                            continue
                        }
                        if (outType != "direct" && outType != "block") {
                            if (!outObj.has("tcp_keep_alive_interval")) {
                                outObj.put("tcp_keep_alive_interval", "15s")
                            }
                            if (!outObj.has("connect_timeout")) {
                                outObj.put("connect_timeout", "10s")
                            }
                        }
                        // Normalize Hysteria2 server_ports (must be JSONArray with start:end syntax)
                        if (outObj.optString("type").equals("hysteria2", ignoreCase = true)) {
                            val sPorts = outObj.opt("server_ports")
                            if (sPorts is String && sPorts.isNotBlank()) {
                                val arr = JSONArray()
                                sPorts.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { p ->
                                    val formatted = if (p.contains("-")) {
                                        "${p.substringBefore("-").trim()}:${p.substringAfter("-").trim()}"
                                    } else {
                                        p
                                    }
                                    arr.put(formatted)
                                }
                                outObj.put("server_ports", arr)
                            } else if (sPorts is JSONArray) {
                                val arr = JSONArray()
                                for (idx in 0 until sPorts.length()) {
                                    val p = sPorts.optString(idx)
                                    val formatted = if (p.contains("-")) {
                                        "${p.substringBefore("-").trim()}:${p.substringAfter("-").trim()}"
                                    } else {
                                        p
                                    }
                                    arr.put(formatted)
                                }
                                outObj.put("server_ports", arr)
                            }
                        }
                        cleanOutbounds.put(outObj)
                    }
                    root.put("outbounds", cleanOutbounds)
                }

                // 2. Rebuild route.rules: DNS hijack/direct rules MUST come first
                val routeObj = root.optJSONObject("route")
                if (routeObj != null) {
                    val existingRules = routeObj.optJSONArray("rules") ?: JSONArray()
                    val orderedRules = JSONArray()

                    if (mode == TunnelMode.VPN) {
                        orderedRules.put(JSONObject().apply {
                            put("port", JSONArray().put(53))
                            put("action", "hijack-dns")
                        })
                        orderedRules.put(JSONObject().apply {
                            put("protocol", "dns")
                            put("action", "hijack-dns")
                        })
                    }

                    for (i in 0 until existingRules.length()) {
                        val rule = existingRules.optJSONObject(i) ?: continue
                        val action = rule.optString("action")
                        val outbound = rule.optString("outbound")
                        // Skip existing standalone DNS rules that we just prepended
                        if (action.equals("hijack-dns", ignoreCase = true)) continue
                        if (outbound.equals("dns", ignoreCase = true) || outbound.equals("dns-out", ignoreCase = true)) continue
                        val portArr = rule.optJSONArray("port")
                        if (portArr != null && portArr.length() == 1 && portArr.optInt(0) == 53 && (outbound == "direct" || action == "hijack-dns")) continue
                        if (rule.optString("protocol") == "dns" && (outbound == "direct" || action == "hijack-dns")) continue
                        orderedRules.put(rule)
                    }
                    routeObj.put("rules", orderedRules)
                }

                // 3. Install the app-wide DNS policy. The raw profile DNS is
                //    intentionally replaced so the setting works for every profile.
                root.put("dns", buildSingboxDns(dnsMode, dohUrl))

                // 4. Sing-box 1.12+ requires an explicit resolver for dialing
                //    outbound server domains (route.default_domain_resolver).
                ensureSingboxDialResolver(root)

                // 5. Apply custom hosts rules
                applyCustomHostsToSingbox(root, customHosts)
            } else if (targetCore == CoreType.XRAY) {
                applyCustomHostsToXray(root, customHosts)
            }

            root.toString(2)
        } catch (_: Exception) {
            jsonStr
        }
    }

    private fun buildSingboxDns(dnsMode: DnsMode, dohUrl: String): JSONObject {
        val servers = JSONArray()
        when (dnsMode) {
            DnsMode.SYSTEM -> {
                servers.put(createSingboxDnsServer("77.88.8.8", "direct-dns", ""))
                servers.put(createSingboxDnsServer("8.8.8.8", "direct-dns-fallback", ""))
                servers.put(createSingboxDnsServer("1.1.1.1", "direct-dns-cf", ""))
            }
            DnsMode.SERVER -> {
                servers.put(createSingboxDnsServer("1.1.1.1", "remote-dns", "proxy"))
                servers.put(createSingboxDnsServer("8.8.8.8", "remote-dns-fallback", "proxy"))
                servers.put(createSingboxDnsServer("77.88.8.8", "direct-dns", ""))
                servers.put(createSingboxDnsServer("8.8.8.8", "direct-dns-alt", ""))
            }
            DnsMode.CUSTOM -> {
                val custom = dohUrl.trim().ifBlank { "1.1.1.1" }
                servers.put(createSingboxDnsServer(custom, "remote-dns", "proxy"))
                servers.put(createSingboxDnsServer("77.88.8.8", "direct-dns", ""))
                servers.put(createSingboxDnsServer("8.8.8.8", "direct-dns-fallback", ""))
                servers.put(createSingboxDnsServer("1.1.1.1", "direct-dns-cf", ""))
            }
        }
        return JSONObject().apply {
            put("servers", servers)
            put("strategy", "prefer_ipv4")
            put("independent_cache", true)
            put("final", if (dnsMode != DnsMode.SYSTEM) "remote-dns" else "direct-dns")
        }
    }

    /**
     * Ensures the config has a non-proxy DNS server for resolving proxy server domains.
     * Without route.default_domain_resolver (or per-outbound domain_resolver),
     * sing-box 1.12+ cannot dial an outbound whose server is a domain name.
     */
    private fun ensureSingboxDialResolver(root: JSONObject) {
        val dnsObj = root.optJSONObject("dns")
            ?: JSONObject().apply { root.put("dns", this) }
        val servers = dnsObj.optJSONArray("servers")
            ?: JSONArray().apply { dnsObj.put("servers", this) }

        var directTag = findDirectDnsTag(servers)
        if (directTag == null) {
            directTag = if (hasDnsServerTag(servers, "direct-dns")) "direct-dns-fallback" else "direct-dns"
            servers.put(createSingboxDnsServer("77.88.8.8", directTag, ""))
        }

        val route = root.optJSONObject("route")
            ?: JSONObject().apply { root.put("route", this) }
        route.put("default_domain_resolver", directTag)

        // Legacy DNS rules attached to outbounds were replaced by
        // domain_resolver / route.default_domain_resolver in sing-box 1.12.
        val rules = dnsObj.optJSONArray("rules") ?: return
        val filtered = JSONArray()
        for (i in 0 until rules.length()) {
            val rule = rules.optJSONObject(i) ?: continue
            if (!rule.has("outbound")) {
                filtered.put(rule)
            }
        }
        if (filtered.length() == 0) {
            dnsObj.remove("rules")
        } else {
            dnsObj.put("rules", filtered)
        }
    }

    private fun findDirectDnsTag(servers: JSONArray): String? {
        for (i in 0 until servers.length()) {
            val sObj = servers.optJSONObject(i) ?: continue
            val tag = sObj.optString("tag")
            val detour = sObj.optString("detour")
            if (tag == "direct-dns" || detour == "direct") {
                return tag.ifBlank { "direct-dns" }
            }
        }
        for (i in 0 until servers.length()) {
            val sObj = servers.optJSONObject(i) ?: continue
            val tag = sObj.optString("tag")
            val detour = sObj.optString("detour")
            if (detour.isEmpty() || detour == "direct") {
                if (tag.isNotBlank()) return tag
            }
        }
        return null
    }

    private fun hasDnsServerTag(servers: JSONArray, tag: String): Boolean {
        for (i in 0 until servers.length()) {
            if (servers.optJSONObject(i)?.optString("tag") == tag) return true
        }
        return false
    }

    private fun createSingboxInbound(mode: TunnelMode, socksListen: String): JSONObject {
        return if (mode == TunnelMode.SOCKS5) {
            val host = socksListen.substringBefore(":").ifBlank { "127.0.0.1" }
            val port = socksListen.substringAfter(":").toIntOrNull() ?: 1080
            JSONObject().apply {
                put("type", "socks")
                put("tag", "socks-in")
                put("listen", host)
                put("listen_port", port)
            }
        } else {
            JSONObject().apply {
                put("type", "tun")
                put("tag", "tun-in")
                put("address", JSONArray().apply {
                    put("172.19.0.1/30")
                })
                put("mtu", 1420)
                put("auto_route", false)
                put("strict_route", false)
                put("stack", "gvisor")
            }
        }
    }

    private fun createXrayInbound(mode: TunnelMode, socksListen: String): JSONArray {
        val sniffing = JSONObject().apply {
            put("enabled", true)
            put("destOverride", JSONArray().put("http").put("tls").put("quic"))
        }
        return if (mode == TunnelMode.SOCKS5) {
            val host = socksListen.substringBefore(":").ifBlank { "127.0.0.1" }
            val port = socksListen.substringAfter(":").toIntOrNull() ?: 1080
            JSONArray().put(JSONObject().apply {
                put("tag", "socks-in")
                put("port", port)
                put("listen", host)
                put("protocol", "socks")
                put("settings", JSONObject().apply {
                    put("auth", "noauth")
                    put("udp", true)
                })
                put("sniffing", sniffing)
            })
        } else {
            JSONArray().put(JSONObject().apply {
                put("tag", "tun-in")
                put("port", 0)
                put("protocol", "tun")
                put("settings", JSONObject().apply {
                    put("name", "tun0")
                    put("mtu", 1500)
                })
                put("sniffing", sniffing)
            })
        }
    }

    private fun completeXrayConfig(
        root: JSONObject,
        proxyOutbound: JSONObject,
        mode: TunnelMode,
        socksListen: String = "127.0.0.1:1080",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = "",
        dohUrl: String = "https://1.1.1.1/dns-query"
    ): String {
        if (!root.has("inbounds")) {
            root.put("inbounds", createXrayInbound(mode, socksListen))
        }
        if (!root.has("log")) {
            root.put("log", JSONObject().put("loglevel", "debug"))
        }

        val directOutbound = JSONObject().apply {
            put("tag", "direct")
            put("protocol", "freedom")
            put("settings", JSONObject())
        }
        val streamSettings = proxyOutbound.optJSONObject("streamSettings") ?: JSONObject().also { proxyOutbound.put("streamSettings", it) }
        val sockopt = streamSettings.optJSONObject("sockopt") ?: JSONObject().also { streamSettings.put("sockopt", it) }
        if (!sockopt.has("tcpKeepAliveInterval")) {
            sockopt.put("tcpKeepAliveInterval", 15)
        }
        if (!sockopt.has("tcpKeepAliveIdle")) {
            sockopt.put("tcpKeepAliveIdle", 15)
        }
        root.put("outbounds", JSONArray().put(proxyOutbound).put(directOutbound))

        val inboundTag = if (mode == TunnelMode.SOCKS5) "socks-in" else "tun-in"
        val dnsOutbound = JSONObject().apply {
            put("tag", "dns-out")
            put("protocol", "dns")
            put("settings", JSONObject())
        }
        root.put("outbounds", JSONArray().put(proxyOutbound).put(directOutbound).put(dnsOutbound))

        root.put("routing", JSONObject().apply {
            put("domainStrategy", if (dnsMode == DnsMode.SYSTEM) "UseIP" else "AsIs")
            val rules = JSONArray().apply {
                if (mode == TunnelMode.VPN) {
                    put(JSONObject().apply {
                        put("type", "field")
                        put("port", "53")
                        put("outboundTag", "dns-out")
                    })
                    put(JSONObject().apply {
                        put("type", "field")
                        put("protocol", JSONArray().put("dns"))
                        put("outboundTag", "dns-out")
                    })
                }
                put(JSONObject().apply {
                    put("type", "field")
                    put("inboundTag", JSONArray().put(inboundTag))
                    put("outboundTag", "proxy")
                })
            }
            put("rules", rules)
        })

        val dnsObj = root.optJSONObject("dns") ?: JSONObject().also { root.put("dns", it) }
        val servers = JSONArray()
        when (dnsMode) {
            DnsMode.SYSTEM -> {
                servers.put("localhost")
                servers.put("77.88.8.8")
            }
            DnsMode.SERVER -> {
                servers.put("1.1.1.1")
                servers.put("8.8.8.8")
            }
            DnsMode.CUSTOM -> {
                if (dohUrl.isNotBlank() && !dohUrl.equals("local", ignoreCase = true)) servers.put(dohUrl)
                servers.put("1.1.1.1")
                servers.put("8.8.8.8")
            }
        }
        dnsObj.put("servers", servers)

        applyCustomHostsToXray(root, customHosts)
        return root.toString(2)
    }

    private fun completeSingboxConfig(
        root: JSONObject,
        proxyOutbound: JSONObject,
        mode: TunnelMode,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        if (!root.has("inbounds")) {
            root.put("inbounds", JSONArray().put(createSingboxInbound(mode, socksListen)))
        }
        if (!root.has("log")) {
            root.put("log", JSONObject().apply {
                put("level", "debug")
            })
        }

        val outType = proxyOutbound.optString("type").lowercase()
        if (outType != "direct" && outType != "block" && outType != "dns") {
            if (!proxyOutbound.has("tcp_keep_alive_interval")) {
                proxyOutbound.put("tcp_keep_alive_interval", "15s")
            }
            if (!proxyOutbound.has("connect_timeout")) {
                proxyOutbound.put("connect_timeout", "10s")
            }
        }
        val directOutbound = JSONObject().apply {
            put("type", "direct")
            put("tag", "direct")
        }
        val outbounds = JSONArray().put(proxyOutbound).put(directOutbound)
        val inboundTag = if (mode == TunnelMode.SOCKS5) "socks-in" else "tun-in"

        root.put("dns", buildSingboxDns(dnsMode, dohUrl))
        root.put("outbounds", outbounds)

        if (mode == TunnelMode.VPN) {
            root.put("route", JSONObject().apply {
                put("auto_detect_interface", false)
                val rules = JSONArray().apply {
                    put(JSONObject().apply {
                        put("port", JSONArray().put(53))
                        put("action", "hijack-dns")
                    })
                    put(JSONObject().apply {
                        put("protocol", "dns")
                        put("action", "hijack-dns")
                    })
                    put(JSONObject().apply {
                        put("action", "sniff")
                    })
                    put(JSONObject().apply {
                        put("inbound", inboundTag)
                        put("outbound", "proxy")
                    })
                }
                put("rules", rules)
            })
        } else {
            root.put("route", JSONObject().apply {
                put("auto_detect_interface", false)
                val rules = JSONArray().apply {
                    put(JSONObject().apply {
                        put("action", "sniff")
                    })
                    put(JSONObject().apply {
                        put("inbound", inboundTag)
                        put("outbound", "proxy")
                    })
                }
                put("rules", rules)
            })
        }

        ensureSingboxDialResolver(root)
        applyCustomHostsToSingbox(root, customHosts)
        return root.toString(2)
    }

    fun parseHosts(hostsText: String): List<Pair<String, String>> {
        if (hostsText.isBlank()) return emptyList()
        val list = mutableListOf<Pair<String, String>>()
        hostsText.lines().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith(";")) return@forEach
            val parts = trimmed.split(Regex("\\s+"))
            if (parts.size >= 2) {
                val ip = parts[0].trim()
                val domain = parts[1].trim().removeSuffix(".")
                if (ip.isNotEmpty() && domain.isNotEmpty()) {
                    list.add(Pair(domain, ip))
                }
            }
        }
        return list
    }

    private fun applyCustomHostsToSingbox(root: JSONObject, customHosts: String) {
        val hostRules = parseHosts(customHosts)
        if (hostRules.isEmpty()) return

        val blockedDomains = hostRules.filter {
            it.second == "127.0.0.1" || it.second == "0.0.0.0" || it.second == "::1" || it.second == "::"
        }.map { it.first }

        if (blockedDomains.isEmpty()) return

        val dnsObj = root.optJSONObject("dns") ?: JSONObject().also { root.put("dns", it) }
        val servers = dnsObj.optJSONArray("servers") ?: JSONArray().also { dnsObj.put("servers", it) }
        servers.put(JSONObject().apply {
            put("tag", "block-dns")
            put("type", "rcode")
            put("address", "rcode://refused")
        })

        val dnsRules = dnsObj.optJSONArray("rules") ?: JSONArray().also { dnsObj.put("rules", it) }
        val blockedArr = JSONArray()
        blockedDomains.forEach { blockedArr.put(it) }
        dnsRules.put(0, JSONObject().apply {
            put("domain", blockedArr)
            put("server", "block-dns")
            put("disable_cache", true)
        })

        val outbounds = root.optJSONArray("outbounds") ?: JSONArray().also { root.put("outbounds", it) }
        var hasBlockOutbound = false
        for (i in 0 until outbounds.length()) {
            if (outbounds.optJSONObject(i)?.optString("tag") == "block") {
                hasBlockOutbound = true
                break
            }
        }
        if (!hasBlockOutbound) {
            outbounds.put(JSONObject().apply {
                put("type", "block")
                put("tag", "block")
            })
        }

        val routeObj = root.optJSONObject("route") ?: JSONObject().also { root.put("route", it) }
        val routeRules = routeObj.optJSONArray("rules") ?: JSONArray().also { routeObj.put("rules", it) }
        routeRules.put(0, JSONObject().apply {
            put("domain", blockedArr)
            put("outbound", "block")
        })
    }

    private fun applyCustomHostsToXray(root: JSONObject, customHosts: String) {
        val hostRules = parseHosts(customHosts)
        if (hostRules.isEmpty()) return

        val dnsObj = root.optJSONObject("dns") ?: JSONObject().also { root.put("dns", it) }
        val hostsObj = dnsObj.optJSONObject("hosts") ?: JSONObject().also { dnsObj.put("hosts", it) }
        hostRules.forEach { (domain, ip) ->
            hostsObj.put(domain, ip)
        }
        if (!dnsObj.has("servers")) {
            dnsObj.put("servers", JSONArray().put("1.1.1.1").put("localhost"))
        }
    }

    private fun parseUriHostPort(afterScheme: String): Triple<String, String, Int> {
        val withoutFrag = afterScheme.substringBefore("#")
        val atIdx = withoutFrag.lastIndexOf('@')
        val rawAuth = if (atIdx >= 0) withoutFrag.substring(0, atIdx).trim() else ""
        val remainder = if (atIdx >= 0) withoutFrag.substring(atIdx + 1) else withoutFrag
        val hostPart = remainder.substringBefore('?').substringBefore('/').trim()

        val auth = try {
            URLDecoder.decode(rawAuth.replace("+", "%2B"), StandardCharsets.UTF_8.name())
        } catch (_: Exception) {
            rawAuth
        }

        val host: String
        val port: Int
        if (hostPart.startsWith("[")) {
            val closeBracket = hostPart.indexOf(']')
            host = hostPart.substring(1, closeBracket)
            val colonIdx = hostPart.indexOf(':', closeBracket)
            port = if (colonIdx >= 0) hostPart.substring(colonIdx + 1).trim().toIntOrNull() ?: 443 else 443
        } else if (hostPart.contains(":")) {
            val colonIdx = hostPart.lastIndexOf(':')
            host = hostPart.substring(0, colonIdx).trim()
            port = hostPart.substring(colonIdx + 1).trim().toIntOrNull() ?: 443
        } else {
            host = hostPart.trim()
            port = 443
        }

        return Triple(auth, host, port)
    }

    private fun parseQueryParams(uri: String): Map<String, String> {
        val queryPart = uri.substringBefore("#").substringAfter("?", "")
        if (queryPart.isBlank()) return emptyMap()

        val map = mutableMapOf<String, String>()
        for (param in queryPart.split("&")) {
            val eq = param.indexOf('=')
            if (eq > 0) {
                val k = param.substring(0, eq).trim().lowercase()
                val rawVal = param.substring(eq + 1).trim()
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

    // 1. VLESS
    private fun buildVless(
        uri: String,
        targetCore: CoreType,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        val withoutScheme = uri.substring(uri.indexOf("://") + 3)
        val (uuid, host, port) = parseUriHostPort(withoutScheme)
        val params = parseQueryParams(uri)

        val security = params["security"] ?: "none"
        val rawType = params["type"] ?: "tcp"
        val transport = if (rawType.equals("raw", ignoreCase = true)) "tcp" else rawType.lowercase()
        val flow = params["flow"] ?: ""
        val sni = params["sni"] ?: params["host"] ?: host
        val fp = params["fp"] ?: "chrome"
        val pbk = params["pbk"] ?: ""
        val sid = params["sid"] ?: ""
        val spx = params["spx"] ?: ""
        val path = params["path"] ?: ""
        val wsHost = params["host"] ?: sni
        val serviceName = params["servicename"] ?: params["service_name"] ?: ""
        val xmode = params["mode"] ?: "packet-up"
        val alpnRaw = params["alpn"] ?: ""
        val insecure = params["insecure"] == "1" || params["allowinsecure"] == "1" || params["insecure"] == "true"

        val alpnList = if (alpnRaw.isNotBlank()) {
            alpnRaw.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        } else {
            listOf("h2", "http/1.1")
        }

        return if (targetCore == CoreType.XRAY) {
            val root = JSONObject()
            root.put("log", JSONObject().put("loglevel", "warning"))
            root.put("inbounds", createXrayInbound(mode, socksListen))

            val vlessOutbound = JSONObject().apply {
                put("tag", "proxy")
                put("protocol", "vless")
                put("settings", JSONObject().apply {
                    val users = JSONArray().apply {
                        put(JSONObject().apply {
                            put("id", uuid)
                            put("encryption", "none")
                            if (flow.isNotBlank()) put("flow", flow)
                        })
                    }
                    val vnext = JSONArray().apply {
                        put(JSONObject().apply {
                            put("address", host)
                            put("port", port)
                            put("users", users)
                        })
                    }
                    put("vnext", vnext)
                })

                val streamSettings = JSONObject()
                val netType = if (transport == "xhttp" || transport == "splithttp") "xhttp" else transport
                streamSettings.put("network", netType)
                streamSettings.put("security", security)

                if (security.equals("reality", ignoreCase = true)) {
                    val reality = JSONObject().apply {
                        put("show", false)
                        put("fingerprint", fp)
                        put("serverName", sni)
                        put("publicKey", pbk)
                        put("shortId", sid)
                        if (spx.isNotBlank()) put("spiderX", spx)
                    }
                    streamSettings.put("realitySettings", reality)
                } else if (security.equals("tls", ignoreCase = true)) {
                    val tls = JSONObject().apply {
                        put("serverName", sni)
                        put("fingerprint", fp)
                        put("alpn", JSONArray(alpnList))
                        if (insecure) put("allowInsecure", true)
                    }
                    streamSettings.put("tlsSettings", tls)
                }

                when (netType) {
                    "ws" -> {
                        val wsSettings = JSONObject().apply {
                            if (path.isNotBlank()) put("path", path)
                            if (wsHost.isNotBlank()) put("headers", JSONObject().put("Host", wsHost))
                        }
                        streamSettings.put("wsSettings", wsSettings)
                    }
                    "grpc" -> {
                        val grpcSettings = JSONObject().apply {
                            if (serviceName.isNotBlank()) put("serviceName", serviceName)
                            put("multiMode", true)
                        }
                        streamSettings.put("grpcSettings", grpcSettings)
                    }
                    "xhttp", "splithttp" -> {
                        val xhttpSettings = JSONObject().apply {
                            if (path.isNotBlank()) put("path", path)
                            if (wsHost.isNotBlank()) put("host", wsHost)
                            put("mode", xmode)
                        }
                        streamSettings.put("xhttpSettings", xhttpSettings)
                    }
                }
                put("streamSettings", streamSettings)
            }

            completeXrayConfig(root, vlessOutbound, mode, socksListen, dnsMode, customHosts, dohUrl)
        } else {
            // Sing-box configuration
            val root = JSONObject()
            root.put("log", JSONObject().put("level", "debug"))
            root.put("inbounds", JSONArray().put(createSingboxInbound(mode, socksListen)))

            val proxyOutbound = JSONObject().apply {
                put("type", "vless")
                put("tag", "proxy")
                put("server", host)
                put("server_port", port)
                put("uuid", uuid)
                if (flow.isNotBlank()) put("flow", flow)

                if (security.equals("reality", ignoreCase = true) || security.equals("tls", ignoreCase = true)) {
                    val tlsObj = JSONObject().apply {
                        put("enabled", true)
                        put("server_name", sni)
                        if (insecure) put("insecure", true)
                        if (security.equals("reality", ignoreCase = true)) {
                            put("reality", JSONObject().apply {
                                put("enabled", true)
                                put("public_key", pbk)
                                put("short_id", sid)
                            })
                        }
                        if (fp.isNotBlank()) {
                            put("utls", JSONObject().apply {
                                put("enabled", true)
                                put("fingerprint", fp)
                            })
                        }
                    }
                    put("tls", tlsObj)
                }

                when (transport) {
                    "ws" -> {
                        put("transport", JSONObject().apply {
                            put("type", "ws")
                            if (path.isNotBlank()) put("path", path)
                            if (wsHost.isNotBlank()) put("headers", JSONObject().put("Host", wsHost))
                        })
                    }
                    "grpc" -> {
                        put("transport", JSONObject().apply {
                            put("type", "grpc")
                            if (serviceName.isNotBlank()) put("service_name", serviceName)
                        })
                    }
                    "http", "xhttp", "splithttp" -> {
                        put("transport", JSONObject().apply {
                            put("type", "http")
                            if (path.isNotBlank()) put("path", path)
                            if (wsHost.isNotBlank()) put("host", JSONArray().put(wsHost))
                        })
                    }
                }
                put("packet_encoding", "xudp")
            }

            completeSingboxConfig(root, proxyOutbound, mode, socksListen, dohUrl, dnsMode, customHosts)
        }
    }

    // 2. VMess
    private fun buildVmess(
        uri: String,
        targetCore: CoreType,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        val payload = uri.substring(uri.indexOf("://") + 3).substringBefore("#")
        val decoded = tryDecodeBase64(payload) ?: "{}"
        val json = try { JSONObject(decoded) } catch (_: Exception) { JSONObject() }

        val host = json.optString("add", "127.0.0.1")
        val port = json.opt("port")?.toString()?.toIntOrNull() ?: 443
        val uuid = json.optString("id", "")
        val aid = json.opt("aid")?.toString()?.toIntOrNull() ?: 0
        val net = json.optString("net", "tcp").lowercase()
        val tls = json.optString("tls", "none").lowercase()
        val sni = json.optString("sni", json.optString("host", host))
        val path = json.optString("path", "")
        val hostHeader = json.optString("host", "")

        val root = JSONObject()
        return if (targetCore == CoreType.XRAY) {
            root.put("log", JSONObject().put("loglevel", "warning"))
            root.put("inbounds", createXrayInbound(mode, socksListen))

            val vmessOutbound = JSONObject().apply {
                put("tag", "proxy")
                put("protocol", "vmess")
                put("settings", JSONObject().apply {
                    put("vnext", JSONArray().put(JSONObject().apply {
                        put("address", host)
                        put("port", port)
                        put("users", JSONArray().put(JSONObject().apply {
                            put("id", uuid)
                            put("alterId", aid)
                            put("security", "auto")
                        }))
                    }))
                })

                val streamSettings = JSONObject()
                streamSettings.put("network", net)
                if (tls == "tls") {
                    streamSettings.put("security", "tls")
                    streamSettings.put("tlsSettings", JSONObject().apply {
                        if (sni.isNotBlank()) put("serverName", sni)
                    })
                }
                if (net == "ws") {
                    streamSettings.put("wsSettings", JSONObject().apply {
                        if (path.isNotBlank()) put("path", path)
                        if (hostHeader.isNotBlank()) put("headers", JSONObject().put("Host", hostHeader))
                    })
                }
                put("streamSettings", streamSettings)
            }
            completeXrayConfig(root, vmessOutbound, mode, socksListen, dnsMode, customHosts, dohUrl)
        } else {
            root.put("log", JSONObject().put("level", "warn"))
            root.put("inbounds", JSONArray().put(createSingboxInbound(mode, socksListen)))

            val vmessOutbound = JSONObject().apply {
                put("type", "vmess")
                put("tag", "proxy")
                put("server", host)
                put("server_port", port)
                put("uuid", uuid)
                put("alter_id", aid)
                put("security", "auto")
                if (tls == "tls") {
                    put("tls", JSONObject().apply {
                        put("enabled", true)
                        if (sni.isNotBlank()) put("server_name", sni)
                    })
                }
                if (net == "ws") {
                    put("transport", JSONObject().apply {
                        put("type", "ws")
                        if (path.isNotBlank()) put("path", path)
                        if (hostHeader.isNotBlank()) put("headers", JSONObject().put("Host", hostHeader))
                    })
                    put("packet_encoding", "xudp")
                }
            }
            completeSingboxConfig(root, vmessOutbound, mode, socksListen, dohUrl, dnsMode, customHosts)
        }
    }

    // 3. Trojan
    private fun buildTrojan(
        uri: String,
        targetCore: CoreType,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        val withoutScheme = uri.substring(uri.indexOf("://") + 3)
        val (password, host, port) = parseUriHostPort(withoutScheme)
        val params = parseQueryParams(uri)
        val sni = params["sni"] ?: host

        val root = JSONObject()
        return if (targetCore == CoreType.XRAY) {
            root.put("log", JSONObject().put("loglevel", "warning"))
            root.put("inbounds", createXrayInbound(mode, socksListen))

            val trojanOutbound = JSONObject().apply {
                put("tag", "proxy")
                put("protocol", "trojan")
                put("settings", JSONObject().apply {
                    put("servers", JSONArray().put(JSONObject().apply {
                        put("address", host)
                        put("port", port)
                        put("password", password)
                    }))
                })
                put("streamSettings", JSONObject().apply {
                    put("security", "tls")
                    put("tlsSettings", JSONObject().put("serverName", sni))
                })
            }
            completeXrayConfig(root, trojanOutbound, mode, socksListen, dnsMode, customHosts, dohUrl)
        } else {
            root.put("log", JSONObject().put("level", "warn"))
            root.put("inbounds", JSONArray().put(createSingboxInbound(mode, socksListen)))

            val trojanOutbound = JSONObject().apply {
                put("type", "trojan")
                put("tag", "proxy")
                put("server", host)
                put("server_port", port)
                put("password", password)
                put("tls", JSONObject().apply {
                    put("enabled", true)
                    put("server_name", sni)
                })
                put("packet_encoding", "xudp")
            }
            completeSingboxConfig(root, trojanOutbound, mode, socksListen, dohUrl, dnsMode, customHosts)
        }
    }

    // 4. Shadowsocks
    private fun buildShadowsocks(
        uri: String,
        targetCore: CoreType,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        val withoutScheme = uri.substring(uri.indexOf("://") + 3).substringBefore("#")
        var method = "aes-256-gcm"
        var password = ""
        var host = "127.0.0.1"
        var port = 8388

        if (withoutScheme.contains("@")) {
            val authPart = withoutScheme.substringBefore("@")
            val hostPortPart = withoutScheme.substringAfter("@").substringBefore("?").substringBefore("/")
            val decodedAuth = tryDecodeBase64(authPart) ?: authPart
            if (decodedAuth.contains(":")) {
                method = decodedAuth.substringBefore(":")
                password = decodedAuth.substringAfter(":")
            }
            if (hostPortPart.contains(":")) {
                host = hostPortPart.substringBefore(":")
                port = hostPortPart.substringAfter(":").toIntOrNull() ?: 8388
            }
        } else {
            val decoded = tryDecodeBase64(withoutScheme) ?: ""
            if (decoded.contains("@")) {
                val auth = decoded.substringBefore("@")
                val hp = decoded.substringAfter("@").substringBefore("?").substringBefore("/")
                if (auth.contains(":")) {
                    method = auth.substringBefore(":")
                    password = auth.substringAfter(":")
                }
                if (hp.contains(":")) {
                    host = hp.substringBefore(":")
                    port = hp.substringAfter(":").toIntOrNull() ?: 8388
                }
            }
        }

        val root = JSONObject()
        return if (targetCore == CoreType.XRAY) {
            root.put("log", JSONObject().put("loglevel", "warning"))
            root.put("inbounds", createXrayInbound(mode, socksListen))
            val ssOutbound = JSONObject().apply {
                put("tag", "proxy")
                put("protocol", "shadowsocks")
                put("settings", JSONObject().apply {
                    put("servers", JSONArray().put(JSONObject().apply {
                        put("address", host)
                        put("port", port)
                        put("method", method)
                        put("password", password)
                    }))
                })
            }
            completeXrayConfig(root, ssOutbound, mode, socksListen, dnsMode, customHosts, dohUrl)
        } else {
            root.put("log", JSONObject().put("level", "warn"))
            root.put("inbounds", JSONArray().put(createSingboxInbound(mode, socksListen)))
            val ssOutbound = JSONObject().apply {
                put("type", "shadowsocks")
                put("tag", "proxy")
                put("server", host)
                put("server_port", port)
                put("method", method)
                put("password", password)
            }
            completeSingboxConfig(root, ssOutbound, mode, socksListen, dohUrl, dnsMode, customHosts)
        }
    }

    // 5. TUIC (Sing-box)
    private fun buildTuic(
        uri: String,
        targetCore: CoreType,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        val withoutScheme = uri.substring(uri.indexOf("://") + 3)
        val (auth, host, port) = parseUriHostPort(withoutScheme)
        val params = parseQueryParams(uri)

        val uuid = if (auth.contains(":")) auth.substringBefore(":") else auth
        val password = if (auth.contains(":")) auth.substringAfter(":") else ""
        val cc = params["congestion_control"] ?: "bbr"
        val sni = params["sni"] ?: host

        val root = JSONObject()
        root.put("log", JSONObject().put("level", "warn"))
        root.put("inbounds", JSONArray().put(createSingboxInbound(mode, socksListen)))

        val tuicOutbound = JSONObject().apply {
            put("type", "tuic")
            put("tag", "proxy")
            put("server", host)
            put("server_port", port)
            put("uuid", uuid)
            put("password", password)
            put("congestion_control", cc)
            put("tls", JSONObject().apply {
                put("enabled", true)
                put("server_name", sni)
                put("alpn", JSONArray().put("h3"))
            })
        }

        return completeSingboxConfig(root, tuicOutbound, mode, socksListen, dohUrl, dnsMode, customHosts)
    }

    // 6. Hysteria 2 (Sing-box)
    private fun buildHysteria2(
        uri: String,
        targetCore: CoreType,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        val withoutScheme = uri.substring(uri.indexOf("://") + 3)
        val (parsedPassword, host, port) = parseUriHostPort(withoutScheme)
        val params = parseQueryParams(uri)
        val password = parsedPassword.ifBlank {
            params["auth"] ?: params["password"] ?: params["pwd"] ?: ""
        }
        val sni = params["sni"] ?: params["peer"] ?: host
        val insecure = params["insecure"] == "1" || params["allowinsecure"] == "1" ||
                params["insecure"] == "true" || params["allow_insecure"] == "1"

        val root = JSONObject()
        root.put("log", JSONObject().put("level", "warn"))
        root.put("inbounds", JSONArray().put(createSingboxInbound(mode, socksListen)))

        val hy2Outbound = JSONObject().apply {
            put("type", "hysteria2")
            put("tag", "proxy")
            put("server", host)

            val mport = params["mport"] ?: params["ports"] ?: params["server_ports"]
            if (!mport.isNullOrBlank()) {
                val portsArray = JSONArray()
                mport.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { p ->
                    val formatted = if (p.contains("-")) {
                        val start = p.substringBefore("-").trim()
                        val end = p.substringAfter("-").trim()
                        "$start:$end"
                    } else {
                        p
                    }
                    portsArray.put(formatted)
                }
                put("server_ports", portsArray)
            } else {
                put("server_port", port)
            }

            put("password", password)

            // Obfuscation (Salamander)
            val obfsType = params["obfs"] ?: params["obfs-type"] ?: params["obfs_type"]
            val obfsPassword = params["obfs-password"] ?: params["obfs_password"] ?: params["obfspassword"]
            if (!obfsPassword.isNullOrBlank() || (!obfsType.isNullOrBlank() && obfsType != "none")) {
                val effectiveType = if (!obfsType.isNullOrBlank() && obfsType != "none") obfsType else "salamander"
                put("obfs", JSONObject().apply {
                    put("type", effectiveType)
                    if (!obfsPassword.isNullOrBlank()) {
                        put("password", obfsPassword)
                    }
                })
            }

            // Bandwidth
            val up = parseBandwidthMbps(params["up"] ?: params["upmbps"] ?: params["upload"])
            val down = parseBandwidthMbps(params["down"] ?: params["downmbps"] ?: params["download"])
            if (up > 0) put("up_mbps", up)
            if (down > 0) put("down_mbps", down)

            // TLS configuration
            put("tls", JSONObject().apply {
                put("enabled", true)
                put("server_name", sni)
                if (insecure) put("insecure", true)
                val alpn = params["alpn"]
                if (!alpn.isNullOrBlank()) {
                    val alpnArray = JSONArray()
                    alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { alpnArray.put(it) }
                    put("alpn", alpnArray)
                }
                val pin = params["pinsha256"] ?: params["pin"] ?: params["cert_sha256"]
                if (!pin.isNullOrBlank()) {
                    put("pinned_peer_certificate_chain_sha256", JSONArray().put(pin))
                }
            })
        }

        return completeSingboxConfig(root, hy2Outbound, mode, socksListen, dohUrl, dnsMode, customHosts)
    }

    private fun parseBandwidthMbps(raw: String?): Int {
        if (raw.isNullOrBlank()) return 0
        val cleaned = raw.trim().lowercase()
        val digits = cleaned.filter { it.isDigit() }.toIntOrNull() ?: return 0
        return if (cleaned.contains("g")) digits * 1000 else digits
    }

    // 7. ShadowTLS (Sing-box)
    private fun buildShadowTls(
        uri: String,
        targetCore: CoreType,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        val withoutScheme = uri.substring(uri.indexOf("://") + 3)
        val (password, host, port) = parseUriHostPort(withoutScheme)
        val params = parseQueryParams(uri)
        val sni = params["sni"] ?: host

        val root = JSONObject()
        root.put("log", JSONObject().put("level", "warn"))
        root.put("inbounds", JSONArray().put(createSingboxInbound(mode, socksListen)))

        val shadowTlsOutbound = JSONObject().apply {
            put("type", "shadowtls")
            put("tag", "proxy")
            put("server", host)
            put("server_port", port)
            put("password", password)
            put("tls", JSONObject().apply {
                put("enabled", true)
                put("server_name", sni)
            })
        }

        return completeSingboxConfig(root, shadowTlsOutbound, mode, socksListen, dohUrl, dnsMode, customHosts)
    }

    fun buildFreeTurn(
        raw: String,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080"
    ): String {
        val trimmed = raw.trim()
        if (trimmed.startsWith("freeturn://", ignoreCase = true)) {
            val b64 = trimmed.substring("freeturn://".length).substringBefore(" ").trim()
            val decoded = tryDecodeBase64(b64)
            if (decoded != null && decoded.startsWith("{")) {
                return buildFreeTurnFromWireJson(decoded, mode, socksListen)
            }
        }
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            return buildFreeTurnFromWireJson(trimmed, mode, socksListen)
        }
        if (trimmed.contains("-peer")) {
            val pMatch = Regex("""-peer\s+([^\s]+)""").find(trimmed)
            val lMatch = Regex("""-(?:links?)\s+["']?([^"'\s]+)["']?""").find(trimmed)
            val kMatch = Regex("""-obf-key\s+([^\s]+)""").find(trimmed)
            val oMatch = Regex("""-obf-profile\s+([^\s]+)""").find(trimmed)
            val cMatch = Regex("""-client-id\s+([^\s]+)""").find(trimmed)
            val nMatch = Regex("""-n\s+(\d+)""").find(trimmed)
            val spcMatch = Regex("""-streams-per-cred\s+(\d+)""").find(trimmed)
            val tunMatch = Regex("""-tunnel-config\s+["']([^"']+)["']""").find(trimmed)

            val dummy = JSONObject().apply {
                if (pMatch != null) put("peer", pMatch.groupValues[1])
                if (lMatch != null) put("vk", lMatch.groupValues[1])
                if (kMatch != null) put("key", kMatch.groupValues[1])
                if (oMatch != null) put("obf", oMatch.groupValues[1])
                if (cMatch != null) put("clientId", cMatch.groupValues[1])
                if (nMatch != null) put("n", nMatch.groupValues[1].toIntOrNull() ?: 12)
                if (spcMatch != null) put("spc", spcMatch.groupValues[1].toIntOrNull() ?: 12)
                if (tunMatch != null) put("wg", tunMatch.groupValues[1])
            }
            return buildFreeTurnFromWireJson(dummy.toString(), mode, socksListen)
        }
        return trimmed
    }

    private fun buildFreeTurnFromWireJson(
        jsonStr: String,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080"
    ): String {
        return try {
            val root = JSONObject(jsonStr)

            val peer = root.optString("peer", "")
            val clientId = root.optString("clientId", root.optString("cid", ""))
            val provider = root.optString("provider", "vk")

            // VK options
            val vkObj = root.optJSONObject("vk") ?: JSONObject()
            val linksArr = org.json.JSONArray()
            val existingLinks = vkObj.optJSONArray("links")
            if (existingLinks != null && existingLinks.length() > 0) {
                for (i in 0 until existingLinks.length()) {
                    val s = existingLinks.optString(i)
                    if (s.isNotBlank()) linksArr.put(s)
                }
            } else {
                val directVk = root.optString("vk", vkObj.optString("link", root.optString("links", "")))
                if (directVk.isNotBlank()) {
                    directVk.split(',').forEach { item ->
                        val tr = item.trim()
                        if (tr.isNotEmpty()) linksArr.put(tr)
                    }
                }
            }
            val vkFinal = JSONObject().apply {
                put("links", linksArr)
                put("streamsPerCred", vkObj.optInt("streamsPerCred", root.optInt("spc", 12)))
                put("manualCaptcha", true)
                put("platform", vkObj.optString("platform", "desktop"))
            }

            // OBF options
            val obfObj = root.optJSONObject("obf")
            val obfProfile = obfObj?.optString("profile", "")?.ifBlank { null }
                ?: root.optString("obf", "rtpopus3").ifBlank { "rtpopus3" }
            val obfKey = obfObj?.optString("key", "")?.ifBlank { null }
                ?: root.optString("key", "")
            val obfTimingMs = obfObj?.optInt("timingMs", 0) ?: 0
            val obfFinal = JSONObject().apply {
                put("profile", obfProfile)
                put("key", obfKey)
                put("timingMs", obfTimingMs)
            }

            // TURN options
            val turnObj = root.optJSONObject("turn")
            val turnN = turnObj?.optInt("n", 0)?.takeIf { it > 0 }
                ?: root.optInt("n", 12).takeIf { it > 0 } ?: 12
            val turnTransport = turnObj?.optString("transport", "tcp") ?: "tcp"
            val turnHost = turnObj?.optString("host", "") ?: ""
            val turnPort = turnObj?.optString("port", "") ?: ""
            val turnFinal = JSONObject().apply {
                put("n", turnN)
                put("transport", turnTransport)
                put("host", turnHost)
                put("port", turnPort)
            }

            // Proxy options
            val proxyObj = root.optJSONObject("proxy")
            val proxyMode = proxyObj?.optString("mode", "udp") ?: "udp"
            val proxyListen = if (mode == TunnelMode.SOCKS5) socksListen else proxyObj?.optString("listen", "127.0.0.1:9000") ?: "127.0.0.1:9000"
            val proxyFinal = JSONObject().apply {
                put("mode", proxyMode)
                put("listen", proxyListen)
            }

            // Tunnel options (WireGuard / AmneziaWG userspace tunnel)
            val tunnelObj = root.optJSONObject("tunnel")
            val wgConfig = tunnelObj?.optString("config", "")?.ifBlank { null }
                ?: root.optString("wg", "")
            val tunnelMode = if (mode == TunnelMode.SOCKS5) {
                "none"
            } else if (wgConfig.isNotBlank()) {
                val specifiedMode = tunnelObj?.optString("mode", "") ?: ""
                when {
                    specifiedMode == "wg" || specifiedMode == "awg" || specifiedMode == "none" -> specifiedMode
                    isAmneziaWgConfig(wgConfig) -> "awg"
                    else -> "wg"
                }
            } else {
                tunnelObj?.optString("mode", "") ?: ""
            }
            val tunnelMtu = tunnelObj?.optInt("mtu", 1280)?.takeIf { it > 0 } ?: 1280
            val tunnelFinal = JSONObject().apply {
                put("mode", tunnelMode)
                put("config", if (mode == TunnelMode.SOCKS5) "" else wgConfig)
                put("mtu", tunnelMtu)
            }

            // Complete clean ClientJSON
            val clean = JSONObject().apply {
                put("peer", peer)
                if (clientId.isNotBlank()) put("clientId", clientId)
                put("subUrl", root.optString("subUrl", ""))
                put("provider", provider)
                put("routes", false)
                put("turn", turnFinal)
                put("proxy", proxyFinal)
                put("vk", vkFinal)
                put("obf", obfFinal)
                put("dns", JSONObject().apply {
                    put("mode", "auto")
                    put("servers", org.json.JSONArray())
                })
                put("log", JSONObject().apply {
                    put("debug", true)
                })
                put("tunnel", tunnelFinal)
            }
            clean.toString(2)
        } catch (_: Exception) {
            jsonStr
        }
    }

    private fun isAmneziaWgConfig(ini: String): Boolean {
        if (!ini.contains("[Interface]", ignoreCase = true)) return false
        val keys = listOf("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4", "i1", "i2")
        return ini.lines().any { line ->
            val trimmed = line.trim()
            if (trimmed.startsWith("#") || trimmed.startsWith(";") || !trimmed.contains("=")) return@any false
            keys.contains(trimmed.substringBefore("=").trim().lowercase())
        }
    }

    private fun buildGenericProxy(
        uri: String,
        targetCore: CoreType,
        mode: TunnelMode = TunnelMode.VPN,
        socksListen: String = "127.0.0.1:1080",
        dohUrl: String = "https://1.1.1.1/dns-query",
        dnsMode: DnsMode = DnsMode.CUSTOM,
        customHosts: String = ""
    ): String {
        return buildVless(uri, targetCore, mode, socksListen, dohUrl, dnsMode, customHosts)
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

    private fun createSingboxDnsServer(urlOrIp: String, tag: String, detour: String): JSONObject {
        val serverObj = JSONObject().apply {
            put("tag", tag)
            if (detour.isNotBlank() && detour != "direct") put("detour", detour)
        }
        val clean = urlOrIp.trim()
        when {
            clean.equals("local", ignoreCase = true) -> {
                serverObj.put("type", "local")
            }
            clean.startsWith("https://", ignoreCase = true) -> {
                serverObj.put("type", "https")
                val uri = try { java.net.URI(clean) } catch (_: Exception) { null }
                val host = uri?.host ?: clean.removePrefix("https://").substringBefore('/').substringBefore(':')
                val path = if (!uri?.rawPath.isNullOrEmpty()) uri?.rawPath else "/dns-query"
                val port = uri?.port?.takeIf { it > 0 } ?: 443
                serverObj.put("server", host)
                if (port != 443) serverObj.put("server_port", port)
                serverObj.put("path", path)
                if (!isIpAddress(host)) {
                    serverObj.put("domain_resolver", "direct-dns")
                }
            }
            clean.startsWith("h3://", ignoreCase = true) -> {
                serverObj.put("type", "h3")
                val uri = try { java.net.URI(clean) } catch (_: Exception) { null }
                val host = uri?.host ?: clean.removePrefix("h3://").substringBefore('/').substringBefore(':')
                val path = if (!uri?.rawPath.isNullOrEmpty()) uri?.rawPath else "/dns-query"
                val port = uri?.port?.takeIf { it > 0 } ?: 443
                serverObj.put("server", host)
                if (port != 443) serverObj.put("server_port", port)
                serverObj.put("path", path)
                if (!isIpAddress(host)) {
                    serverObj.put("domain_resolver", "direct-dns")
                }
            }
            clean.startsWith("tls://", ignoreCase = true) -> {
                serverObj.put("type", "tls")
                val hostPort = clean.removePrefix("tls://").substringBefore('/')
                val host = hostPort.substringBefore(':')
                val port = hostPort.substringAfter(':', "853").toIntOrNull() ?: 853
                serverObj.put("server", host)
                serverObj.put("server_port", port)
                if (!isIpAddress(host)) {
                    serverObj.put("domain_resolver", "direct-dns")
                }
            }
            clean.startsWith("tcp://", ignoreCase = true) -> {
                serverObj.put("type", "tcp")
                val hostPort = clean.removePrefix("tcp://").substringBefore('/')
                val host = hostPort.substringBefore(':')
                val port = hostPort.substringAfter(':', "53").toIntOrNull() ?: 53
                serverObj.put("server", host)
                serverObj.put("server_port", port)
                if (!isIpAddress(host)) {
                    serverObj.put("domain_resolver", "direct-dns")
                }
            }
            else -> {
                serverObj.put("type", "udp")
                val raw = clean.removePrefix("udp://").substringBefore('/')
                val host = raw.substringBefore(':')
                val port = raw.substringAfter(':', "53").toIntOrNull() ?: 53
                serverObj.put("server", host)
                serverObj.put("server_port", port)
                if (!isIpAddress(host)) {
                    serverObj.put("domain_resolver", "direct-dns")
                }
            }
        }
        return serverObj
    }

    private fun isIpAddress(host: String): Boolean {
        val parts = host.split(".")
        if (parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }) return true
        if (host.contains(":") && host.split(":").size >= 3) return true
        return false
    }
}
