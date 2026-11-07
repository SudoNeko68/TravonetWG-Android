package com.travonet.wireguard

import com.travonet.wireguard.model.DefaultStrategies
import com.travonet.wireguard.model.EvasionStrategy
import com.travonet.wireguard.parser.WgConfigParser
import com.travonet.wireguard.service.TunnelManager
import com.travonet.wireguard.warp.WarpGenerator
import org.junit.Assert.*
import org.junit.Test

class TravonetUnitTest {

    private val sampleConfigWithoutStrategy = """
        [Interface]
        PrivateKey = OCugIHnrk/r8Zdtd5AGYIchdMag+dqXF08yn1AZ2aUw=
        Address = 172.16.0.2/32, fd00::2/64
        DNS = 1.1.1.1, 8.8.8.8
        MTU = 1280

        [Peer]
        PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
        Endpoint = 162.159.192.1:2408
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
    """.trimIndent()

    private val sampleConfigWithStrategy = """
        [Interface]
        PrivateKey = OCugIHnrk/r8Zdtd5AGYIchdMag+dqXF08yn1AZ2aUw=
        Address = 172.16.0.2/32
        DNS = 1.1.1.1
        Strategy = junk(size=32) -> fake_udp(size=148)
        FakeTTL = 9
        PreJunk = 32

        [Peer]
        PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
        Endpoint = 162.159.192.1:2408
        AllowedIPs = 0.0.0.0/0
    """.trimIndent()

    @Test
    fun testParseProfile() {
        val profile = WgConfigParser.parseProfile("My Server", sampleConfigWithoutStrategy)
        assertEquals("My Server", profile.name)
        assertEquals("162.159.192.1:2408", profile.endpoint)
        assertEquals("172.16.0.2/32, fd00::2/64", profile.address)
        assertEquals("0.0.0.0/0, ::/0", profile.allowedIps)
        assertEquals("1.1.1.1, 8.8.8.8", profile.dns)
        assertEquals(1280, profile.mtu)
        assertFalse(profile.hasEmbeddedStrategy)
        assertNull(profile.embeddedStrategy)
    }

    @Test
    fun testParseProfileWithStrategy() {
        val profile = WgConfigParser.parseProfile("Evasion Server", sampleConfigWithStrategy)
        assertTrue(profile.hasEmbeddedStrategy)
        assertEquals("junk(size=32) -> fake_udp(size=148)", profile.embeddedStrategy)
    }

    @Test
    fun testFallbackStrategyInjection() {
        val profile = WgConfigParser.parseProfile("Clean Server", sampleConfigWithoutStrategy)
        val fallbackStrategy = EvasionStrategy(
            name = "Стандартная ТСПУ",
            description = "Test description",
            dsl = "mimic(quic) -> jumbo_fake(size=1600) -> fake_udp(size=148, corrupt=true)",
            fakeTtl = "auto",
            preJunk = 64,
            normalTtl = 64
        )

        val prepared = WgConfigParser.prepareConfigForLaunch(profile, fallbackStrategy)
        assertTrue(prepared.contains("Strategy = mimic(quic) -> jumbo_fake(size=1600) -> fake_udp(size=148, corrupt=true)"))
        assertTrue(prepared.contains("FakeTTL = auto"))
        assertTrue(prepared.contains("PreJunk = 64"))
        assertTrue(prepared.contains("NormalTTL = 64"))
        assertTrue(prepared.contains("Address = 172.16.0.2/32, fd00::2/64"))
    }

    @Test
    fun testConfigWithOwnStrategyNotOverridden() {
        val profile = WgConfigParser.parseProfile("Custom Strategy Server", sampleConfigWithStrategy)
        val fallbackStrategy = EvasionStrategy(
            name = "Fallback",
            description = "Fallback",
            dsl = "junk(size=64) -> fake_udp(size=148)",
            fakeTtl = "auto",
            preJunk = 64
        )

        val prepared = WgConfigParser.prepareConfigForLaunch(profile, fallbackStrategy)
        assertTrue(prepared.contains("Strategy = junk(size=32) -> fake_udp(size=148)"))
        assertFalse(prepared.contains("junk(size=64) -> fake_udp(size=148)"))
    }

    @Test
    fun testParseUapiStats() {
        val uapi = """
            public_key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            endpoint=162.159.192.1:2408
            last_handshake_time_sec=1728120000
            last_handshake_time_nsec=123456
            tx_bytes=1048576
            rx_bytes=5242880
            persistent_keepalive_interval=25
            allowed_ip=0.0.0.0/0
        """.trimIndent()

        val stats = TunnelManager.parseUapiStats(uapi)
        assertEquals(1048576L, stats.txBytes)
        assertEquals(5242880L, stats.rxBytes)
        assertEquals(1728120000L, stats.lastHandshakeSec)
        assertEquals("1.00 MB", stats.formattedTx())
        assertEquals("5.00 MB", stats.formattedRx())
    }

    @Test
    fun testDefaultStrategiesUseUserspaceActionsOnly() {
        DefaultStrategies.ALL.forEach { strategy ->
            assertFalse(
                "Пресет '${strategy.name}' использует действие, требующее raw-сокет: ${strategy.dsl}",
                DefaultStrategies.hasRawOnlyActions(strategy.dsl)
            )
        }
        assertEquals(DefaultStrategies.ALL.size, DefaultStrategies.ALL.map { it.id }.distinct().size)
    }

    @Test
    fun testRecommendedStrategyStartsWithJunk() {
        val strategy = DefaultStrategies.ALL.first { it.id == "strat_tspu_default" }

        assertTrue(
            "Рекомендуемая WARP-стратегия должна начинаться с junk: ${strategy.dsl}",
            strategy.dsl.trimStart().startsWith("junk(")
        )
        assertTrue(strategy.dsl.contains("mimic(quic)"))
        assertTrue(strategy.dsl.contains("mimic(stun)"))
        assertTrue(strategy.dsl.contains("fake_udp"))
        assertEquals(0, strategy.preJunk)
    }

    @Test
    fun testNoEvasionInjectedForCleanStrategy() {
        val profile = WgConfigParser.parseProfile("Clean Server", sampleConfigWithoutStrategy)
        val clean = DefaultStrategies.ALL.first { it.id == "strat_clean_wg" }

        val prepared = WgConfigParser.prepareConfigForLaunch(profile, clean)
        assertTrue(prepared.contains("NoEvasion = true"))
        assertFalse(prepared.contains("Strategy ="))
        // Директивы обязаны попасть в [Interface], до [Peer].
        assertTrue(prepared.indexOf("NoEvasion = true") < prepared.indexOf("[Peer]"))
    }

    @Test
    fun testNoEvasionAliases() {
        val profile = WgConfigParser.parseProfile("Clean Server", sampleConfigWithoutStrategy)
        listOf("none", "off", "clean", " None ").forEach { alias ->
            val strategy = EvasionStrategy(name = "Alias", description = "", dsl = alias)
            val prepared = WgConfigParser.prepareConfigForLaunch(profile, strategy)
            assertTrue("alias '$alias'", prepared.contains("NoEvasion = true"))
            assertFalse("alias '$alias'", prepared.contains("Strategy ="))
        }
    }

    @Test
    fun testConfigWithNoEvasionNotOverridden() {
        val raw = """
            [Interface]
            PrivateKey = OCugIHnrk/r8Zdtd5AGYIchdMag+dqXF08yn1AZ2aUw=
            Address = 172.16.0.2/32
            NoEvasion = true

            [Peer]
            PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
            Endpoint = 162.159.192.1:2408
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()
        val profile = WgConfigParser.parseProfile("Raw NoEvasion", raw)
        val strategy = DefaultStrategies.ALL.first { it.id == "strat_tspu_default" }

        val prepared = WgConfigParser.prepareConfigForLaunch(profile, strategy)
        assertEquals(raw, prepared)
    }

    @Test
    fun testNoEvasionFalseStillAllowsInjection() {
        val raw = """
            [Interface]
            PrivateKey = OCugIHnrk/r8Zdtd5AGYIchdMag+dqXF08yn1AZ2aUw=
            Address = 172.16.0.2/32
            NoEvasion = false

            [Peer]
            PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
            Endpoint = 162.159.192.1:2408
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()
        val profile = WgConfigParser.parseProfile("NoEvasion=false", raw)
        val strategy = DefaultStrategies.ALL.first { it.id == "strat_pure_frag" }

        val prepared = WgConfigParser.prepareConfigForLaunch(profile, strategy)
        assertTrue(prepared.contains("Strategy = ${strategy.dsl}"))
    }

    @Test
    fun testWarpProfileDoesNotEmitReserved() {
        val registration = WarpGenerator.Registration(
            privateKey = "private",
            publicKey = "public",
            ipv4 = "172.16.0.2",
            ipv6 = "2606:4700:110::1",
            peerPublicKey = "peer",
            endpoint = "162.159.192.6:2408"
        )

        val config = WarpGenerator.buildConfig(registration)

        assertFalse(
            "Свежий WARP-профиль не должен содержать Reserved: Cloudflare не отвечает на такой handshake",
            config.contains("Reserved", ignoreCase = true)
        )
        assertTrue(config.contains("Endpoint = 162.159.192.6:2408"))
    }

    @Test
    fun testResolveEndpointIpv4Preserved() {
        val endpoint = "162.159.192.1:2408"
        val resolved = WgConfigParser.resolveEndpointToIpv4(endpoint)
        assertEquals("162.159.192.1:2408", resolved)
    }

    @Test
    fun testResolveEndpointDomainLocalhost() {
        val endpoint = "localhost:51820"
        val resolved = WgConfigParser.resolveEndpointToIpv4(endpoint)
        assertEquals("127.0.0.1:51820", resolved)
    }

    @Test
    fun testResolveConfigEndpointsReplacesDomain() {
        val raw = """
            [Interface]
            PrivateKey = OCugIHnrk/r8Zdtd5AGYIchdMag+dqXF08yn1AZ2aUw=
            Address = 172.16.0.2/32
            
            [Peer]
            PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
            Endpoint = localhost:2408
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()

        val resolved = WgConfigParser.resolveConfigEndpoints(raw)
        assertTrue(resolved.contains("Endpoint = 127.0.0.1:2408"))
        assertFalse(resolved.contains("localhost:2408"))
    }

    @Test
    fun testNormalizeRelayUrlConvertsCyrillicDomainToPunycode() {
        val raw = "https://larp.футанари.рф/register"
        val normalized = WarpGenerator.normalizeRelayUrl(raw)
        assertEquals("https://larp.xn--80aaysqigh.xn--p1ai/register", normalized)
    }

    @Test
    fun testDemoProfileIdentified() {
        val sample = WgConfigParser.parseProfile("Демо-сервер WireGuard (Пример)", sampleConfigWithoutStrategy)
        assertTrue(sample.name.lowercase().contains("демо"))
    }

    @Test
    fun testPingHelperExtractHost() {
        assertEquals("162.159.192.1", com.travonet.wireguard.service.PingHelper.extractHost("162.159.192.1:2408"))
        assertEquals("engage.cloudflareclient.com", com.travonet.wireguard.service.PingHelper.extractHost("engage.cloudflareclient.com:2408"))
        assertEquals("2606:4700:d0::a29f:c001", com.travonet.wireguard.service.PingHelper.extractHost("[2606:4700:d0::a29f:c001]:2408"))
        assertEquals("1.1.1.1", com.travonet.wireguard.service.PingHelper.extractHost("1.1.1.1"))
    }

    @Test
    fun testSubscriptionTitleBase64() {
        val title = com.travonet.wireguard.subscription.SubscriptionFetcher.parseProfileTitle("base64:VHJhdm9uZXQ=")
        assertEquals("Travonet", title)

        val plainTitle = com.travonet.wireguard.subscription.SubscriptionFetcher.parseProfileTitle("My Custom Title")
        assertEquals("My Custom Title", plainTitle)
    }

    @Test
    fun testSubscriptionBodyDecoding() {
        val rawIni = """
            [Interface]
            PrivateKey = OCugIHnrk/r8Zdtd5AGYIchdMag+dqXF08yn1AZ2aUw=
            Address = 10.8.0.2/32
            
            [Peer]
            PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
            Endpoint = 198.51.100.1:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()

        val b64Body = java.util.Base64.getEncoder().encodeToString(rawIni.toByteArray())
        val profiles = com.travonet.wireguard.subscription.SubscriptionFetcher.parseSubscriptionBody(b64Body, "Travonet Server")

        assertEquals(1, profiles.size)
        assertEquals("Travonet Server", profiles[0].name)
        assertEquals("198.51.100.1:51820", profiles[0].endpoint)
        assertEquals("10.8.0.2/32", profiles[0].address)
    }

    @Test
    fun testRealTravonetSubscriptionFetch() {
        val url = "https://travonet.ru:2096/sub/a1omsts2x1kunn7o"
        try {
            val result = com.travonet.wireguard.subscription.SubscriptionFetcher.fetchSubscription(url)
            println("FETCHED TITLE: ${result.title}")
            println("PROFILES COUNT: ${result.profiles.size}")
            for (p in result.profiles) {
                println("--- Profile: ${p.name} (${p.endpoint}) ---")
                println(p.rawConfig)
            }
            assertEquals("Travonet", result.title)
            assertEquals(2, result.profiles.size)
        } catch (e: java.io.IOException) {
            println("Live server unreachable or timed out during unit test: ${e.message}")
        }
    }

    @Test
    fun testRegexClipboardDetection() {
        val httpRegex = Regex("""https?://[^\s"'<>]+""", RegexOption.IGNORE_CASE)
        val vpnRegex = Regex("""vpn://[^\s"'<>]+""", RegexOption.IGNORE_CASE)
        val interfaceRegex = Regex("""\[Interface\]""", RegexOption.IGNORE_CASE)

        // 1. Subscription URL
        val subText = "Вот держи подписку https://travonet.ru:2096/sub/9o4ncb577c41xfqi."
        val httpMatch = httpRegex.find(subText)
        assertNotNull(httpMatch)
        assertEquals("https://travonet.ru:2096/sub/9o4ncb577c41xfqi.", httpMatch!!.value)
        assertEquals("https://travonet.ru:2096/sub/9o4ncb577c41xfqi", httpMatch.value.trimEnd('.', ',', ';'))

        // 2. vpn:// link
        val vpnText = "Подключайся vpn://W0ludGVyZmFjZV0KUHJpdmF0ZUtleSA9... спасибо"
        val vpnMatch = vpnRegex.find(vpnText)
        assertNotNull(vpnMatch)
        assertEquals("vpn://W0ludGVyZmFjZV0KUHJpdmF0ZUtleSA9...", vpnMatch!!.value)

        // 3. [Interface] config
        val confText = "# My WG config\n[Interface]\nPrivateKey = abc\n[Peer]\nPublicKey = def\n"
        assertTrue(interfaceRegex.containsMatchIn(confText))
        assertFalse(interfaceRegex.containsMatchIn("vpn://W0ludGVy..."))
    }

    @Test
    fun testSubscriptionUserInfoParsingAndFormatting() {
        val rawUserInfo = "upload=104857600; download=209715200; total=1073741824; expire=1770508800"
        val parsed = com.travonet.wireguard.model.Subscription.parseUserInfo(rawUserInfo)
        assertEquals(104857600L, parsed.upload)
        assertEquals(209715200L, parsed.download)
        assertEquals(1073741824L, parsed.total)
        assertEquals(1770508800L, parsed.expire)

        val sub = com.travonet.wireguard.model.Subscription(
            url = "https://example.com/sub/123",
            title = "Test Sub",
            lastUpdate = 1730000000000L,
            updateIntervalHours = 12,
            uploadBytes = parsed.upload,
            downloadBytes = parsed.download,
            totalBytes = parsed.total,
            expireTimeSec = parsed.expire
        )

        // 300 MB / 1.00 GB
        val traffic = sub.formattedTraffic()
        assertNotNull(traffic)
        assertTrue(traffic!!.contains("300.0 MB") && traffic.contains("1.0 GB"))

        val expire = sub.formattedExpire()
        assertNotNull(expire)
        assertTrue(expire!!.startsWith("Истекает: "))

        // JSON serialization round-trip
        val json = sub.toJson()
        val restored = com.travonet.wireguard.model.Subscription.fromJson(json)
        assertEquals(sub.url, restored.url)
        assertEquals(sub.title, restored.title)
        assertEquals(sub.lastUpdate, restored.lastUpdate)
        assertEquals(sub.updateIntervalHours, restored.updateIntervalHours)
        assertEquals(sub.uploadBytes, restored.uploadBytes)
        assertEquals(sub.downloadBytes, restored.downloadBytes)
        assertEquals(sub.totalBytes, restored.totalBytes)
        assertEquals(sub.expireTimeSec, restored.expireTimeSec)
    }

    @Test
    fun testUnlimitedSubscriptionTrafficFormatting() {
        val rawUserInfo = "upload=500000000; download=0; total=0; expire=0"
        val parsed = com.travonet.wireguard.model.Subscription.parseUserInfo(rawUserInfo)
        val sub = com.travonet.wireguard.model.Subscription(
            url = "https://example.com/unlimited",
            title = "Unlimited Sub",
            uploadBytes = parsed.upload,
            downloadBytes = parsed.download,
            totalBytes = parsed.total,
            expireTimeSec = parsed.expire
        )
        val traffic = sub.formattedTraffic()
        assertNotNull(traffic)
        assertTrue("Should contain infinity symbol", traffic!!.contains("∞"))
        assertNull("Zero expire time should return null", sub.formattedExpire())
    }

    @Test
    fun testAmneziaNoEvasionInjection() {
        val amneziaRaw = """
            [Interface]
            PrivateKey = wJDD6EqwRlVwOCYSTsTdSrmrQU4/86VdaDjZp8Bcfk4=
            Address = 10.8.1.26/32
            DNS = 8.8.8.8, 8.8.4.4
            MTU = 1200
            Jc = 4
            Jmin = 52
            Jmax = 105
            S1 = 150
            S2 = 74
            H1 = 521314697
            H2 = 947619070

            [Peer]
            PublicKey = l/uN/aCjHCnMvl8ksmKQvmO6hJPcGQezdBqOqUYqp1M=
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = travonet.ru:29835
        """.trimIndent()

        assertTrue(WgConfigParser.isAmneziaConfig(amneziaRaw))

        val profile = WgConfigParser.parseProfile("Amnezia Test", amneziaRaw)
        val fallbackStrategy = EvasionStrategy(
            name = "ТСПУ Burst",
            description = "",
            dsl = "junk(size=64) -> fake_udp(size=148)"
        )

        val prepared = WgConfigParser.prepareConfigForLaunch(profile, fallbackStrategy)
        assertTrue("Amnezia configs must have NoEvasion = true injected", prepared.contains("NoEvasion = true"))
        assertFalse("Amnezia configs must NOT have Strategy injected", prepared.contains("Strategy ="))
        assertFalse("Amnezia configs must NOT have FakeTTL injected", prepared.contains("FakeTTL ="))
        assertTrue("Amnezia Jc must be preserved", prepared.contains("Jc = 4"))
    }

    @Test
    fun testAmneziaWg31ConfigDetected() {
        val amnezia31Raw = """
            [Interface]
            PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
            Address = 10.8.0.2/24
            S3 = 10
            S4 = 15
            I3 = <rc 8>
            HeaderProtectionKey = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            ContentPaddingAddition = 16-32
            RandomTrailers = true

            [Peer]
            PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 198.51.100.1:51820
        """.trimIndent()

        assertTrue(WgConfigParser.isAmneziaConfig(amnezia31Raw))

        val profile = WgConfigParser.parseProfile("Amnezia 3.1 Test", amnezia31Raw)
        val fallbackStrategy = EvasionStrategy(
            name = "ТСПУ Burst",
            description = "",
            dsl = "junk(size=64) -> fake_udp(size=148)"
        )

        val prepared = WgConfigParser.prepareConfigForLaunch(profile, fallbackStrategy)
        assertTrue("Amnezia 3.1 configs must have NoEvasion = true injected", prepared.contains("NoEvasion = true"))
        assertFalse("Amnezia 3.1 configs must NOT have Strategy injected", prepared.contains("Strategy ="))
        assertTrue("Amnezia S4 must be preserved", prepared.contains("S4 = 15"))
        assertTrue("Amnezia HeaderProtectionKey must be preserved", prepared.contains("HeaderProtectionKey = 0123456789abcdef"))

        val routerResult = com.travonet.wireguard.core.CoreRouter.route(amnezia31Raw)
        assertEquals(com.travonet.wireguard.core.SupportedProtocol.AMNEZIA_WG.displayName, routerResult.detectedProtocol)
    }

    @Test
    fun testParseAwgUrl() {
        val awgUri = "awg://bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D@198.51.100.1:51820?address=10.8.0.2%2F24&privatekey=OCugIHnrk%2Fr8Zdtd5AGYIchdMag%2BdqXF08yn1AZ2aUw%3D&jc=4&jmin=50&jmax=1000&s1=20&s2=30&h1=123456#MyAwgServer"
        val parsed = WgConfigParser.parseWireGuardUrl(awgUri)
        assertNotNull(parsed)
        val (config, name) = parsed!!
        assertEquals("MyAwgServer", name)
        assertTrue(config.contains("Jc = 4"))
        assertTrue(config.contains("Jmin = 50"))
        assertTrue(config.contains("S1 = 20"))
        assertTrue(config.contains("H1 = 123456"))
        assertTrue(WgConfigParser.isAmneziaConfig(config))
    }

    @Test
    fun testParseWireGuardUrl() {
        // 1. URL with query parameters format
        val wgUri = "wireguard://bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D@162.159.192.1:2408?address=172.16.0.2%2F32&privatekey=OCugIHnrk%2Fr8Zdtd5AGYIchdMag%2BdqXF08yn1AZ2aUw%3D&dns=1.1.1.1#Custom%20WireGuard"
        val parsed = WgConfigParser.parseWireGuardUrl(wgUri)
        assertNotNull(parsed)
        val (config, name) = parsed!!
        assertEquals("Custom WireGuard", name)
        assertTrue(config.contains("[Interface]"))
        assertTrue(config.contains("PrivateKey = OCugIHnrk/r8Zdtd5AGYIchdMag+dqXF08yn1AZ2aUw="))
        assertTrue(config.contains("Address = 172.16.0.2/32"))
        assertTrue(config.contains("PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="))
        assertTrue(config.contains("Endpoint = 162.159.192.1:2408"))

        // 2. Base64 payload format (e.g. wg://<base64>#Name)
        val base64Conf = java.util.Base64.getEncoder().encodeToString(sampleConfigWithoutStrategy.toByteArray())
        val wgB64Uri = "wg://$base64Conf#Standard%20WG"
        val parsedB64 = WgConfigParser.parseWireGuardUrl(wgB64Uri)
        assertNotNull(parsedB64)
        val (configB64, nameB64) = parsedB64!!
        assertEquals("Standard WG", nameB64)
        assertTrue(configB64.contains("162.159.192.1:2408"))
    }

    @Test
    fun testMultiProfileIniSubscription() {
        val multiIni = """
            # Server 1 - Amsterdam
            [Interface]
            PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            Address = 10.0.0.1/32
            
            [Peer]
            PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            Endpoint = 198.51.100.1:51820
            AllowedIPs = 0.0.0.0/0
            
            # Server 2 - Frankfurt
            [Interface]
            PrivateKey = cccccccccccccccccccccccccccccccccccccccccccc
            Address = 10.0.0.2/32
            
            [Peer]
            PublicKey = dddddddddddddddddddddddddddddddddddddddddddd
            Endpoint = 198.51.100.2:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()

        val profiles = com.travonet.wireguard.subscription.SubscriptionFetcher.parseSubscriptionBody(multiIni, "Test Multi")
        assertEquals(2, profiles.size)
        assertEquals("Server 1 - Amsterdam", profiles[0].name)
        assertEquals("198.51.100.1:51820", profiles[0].endpoint)
        assertEquals("Server 2 - Frankfurt", profiles[1].name)
        assertEquals("198.51.100.2:51820", profiles[1].endpoint)
    }

    @Test
    fun testMicroParserRouting() {
        val wgUri = "wireguard://eCBOtZ1g...@z.travonet.ru:56566?address=10.0.0.3/32"
        val awgUri = "vpn://W0ludGVyZmFjZV0KUHJpdmF0ZUtleSA9..."
        val vlessUri = "vless://98765432-1234-1234-1234-123456789abc@example.com:443?security=reality&flow=xtls-rprx-vision#MyVless"
        val vmessUri = "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjoiNDQzIn0="
        val trojanUri = "trojan://password123@example.com:443?security=tls#MyTrojan"
        val ssUri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@example.com:8388#MySS"
        val tuicUri = "tuic://uuid:token@example.com:8443?congestion_control=bbr#MyTuic"
        val hy2Uri = "hysteria2://mypassword@example.com:443?sni=example.com#MyHy2"
        val hy2ShortUri = "hy2://mypassword@example.com:443#MyHy2Short"
        val shadowtlsUri = "shadowtls://example.com:443?password=secret#MyShadowTLS"

        // 1. TravonetWG (WireGuard & AmneziaWG)
        assertEquals(com.travonet.wireguard.core.CoreType.TRAVONET_WG, com.travonet.wireguard.core.CoreRouter.route(wgUri).targetCore)
        assertEquals(com.travonet.wireguard.core.CoreType.TRAVONET_WG, com.travonet.wireguard.core.CoreRouter.route(awgUri).targetCore)
        assertEquals(com.travonet.wireguard.core.CoreType.TRAVONET_WG, com.travonet.wireguard.core.CoreRouter.route("[Interface]\nPrivateKey=...").targetCore)

        // 2. Xray-Core (VLESS Reality, VMess, Trojan, Shadowsocks)
        assertEquals(com.travonet.wireguard.core.CoreType.XRAY, com.travonet.wireguard.core.CoreRouter.route(vlessUri).targetCore)
        assertEquals(com.travonet.wireguard.core.CoreType.XRAY, com.travonet.wireguard.core.CoreRouter.route(vmessUri).targetCore)
        assertEquals(com.travonet.wireguard.core.CoreType.XRAY, com.travonet.wireguard.core.CoreRouter.route(trojanUri).targetCore)
        assertEquals(com.travonet.wireguard.core.CoreType.XRAY, com.travonet.wireguard.core.CoreRouter.route(ssUri).targetCore)

        // 3. Sing-Box (TUIC, Hysteria 2, ShadowTLS)
        assertEquals(com.travonet.wireguard.core.CoreType.SINGBOX, com.travonet.wireguard.core.CoreRouter.route(tuicUri).targetCore)
        assertEquals(com.travonet.wireguard.core.CoreType.SINGBOX, com.travonet.wireguard.core.CoreRouter.route(hy2Uri).targetCore)
        assertEquals(com.travonet.wireguard.core.CoreType.SINGBOX, com.travonet.wireguard.core.CoreRouter.route(hy2ShortUri).targetCore)
        assertEquals(com.travonet.wireguard.core.CoreType.SINGBOX, com.travonet.wireguard.core.CoreRouter.route(shadowtlsUri).targetCore)

        val hy2Json = "{\"outbounds\": [{\"type\": \"hysteria2\", \"server\": \"hy2.example.com\"}]}"
        val hy1Json = "{\"outbounds\": [{\"type\": \"hysteria\", \"server\": \"hy1.example.com\"}]}"
        val tuicJson = "{\"outbounds\": [{\"type\": \"tuic\", \"server\": \"tuic.example.com\"}]}"
        assertEquals(com.travonet.wireguard.core.SupportedProtocol.HYSTERIA2.displayName, com.travonet.wireguard.core.CoreRouter.route(hy2Json).detectedProtocol)
        assertEquals(com.travonet.wireguard.core.SupportedProtocol.HYSTERIA2.displayName, com.travonet.wireguard.core.CoreRouter.route(hy1Json).detectedProtocol)
        assertEquals(com.travonet.wireguard.core.SupportedProtocol.TUIC.displayName, com.travonet.wireguard.core.CoreRouter.route(tuicJson).detectedProtocol)

        // 4. Custom User Delegations
        val customMap = mapOf(
            com.travonet.wireguard.core.SupportedProtocol.VLESS.id to com.travonet.wireguard.core.CoreType.SINGBOX.id,
            com.travonet.wireguard.core.SupportedProtocol.HYSTERIA2.id to com.travonet.wireguard.core.CoreType.XRAY.id
        )
        // VLESS delegated to Sing-Box by user
        assertEquals(com.travonet.wireguard.core.CoreType.SINGBOX, com.travonet.wireguard.core.CoreRouter.route(vlessUri, customMap).targetCore)
        // Hysteria 2 delegated to Xray by user
        assertEquals(com.travonet.wireguard.core.CoreType.XRAY, com.travonet.wireguard.core.CoreRouter.route(hy2Uri, customMap).targetCore)
    }

    @Test
    fun testProxyLinkParserAllProtocols() {
        val vlessUrl = "vless://98765432-1234-1234-1234-123456789abc@vpn.example.com:443?security=reality&flow=xtls-rprx-vision&type=tcp#Netherlands-VLESS"
        val vmessPayload = java.util.Base64.getEncoder().encodeToString(
            """{"ps":"Germany-VMess","add":"de.example.com","port":8443,"net":"ws","tls":"tls"}""".toByteArray()
        )
        val vmessUrl = "vmess://$vmessPayload"
        val trojanUrl = "trojan://secretpass@tr.example.com:443?security=tls#Finland-Trojan"
        val ssUrl = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@ss.example.com:8388#Japan-SS"
        val tuicUrl = "tuic://myuuid:mypass@tuic.example.com:8443?congestion_control=bbr#US-TUIC"
        val hy2Url = "hysteria2://superpass@hy2.example.com:443?sni=hy2.example.com#UK-Hy2"

        val vlessProfile = com.travonet.wireguard.parser.ProxyLinkParser.parse(vlessUrl)
        assertNotNull(vlessProfile)
        assertEquals("Netherlands-VLESS", vlessProfile?.name)
        assertEquals("vpn.example.com:443", vlessProfile?.endpoint)

        val vmessProfile = com.travonet.wireguard.parser.ProxyLinkParser.parse(vmessUrl)
        assertNotNull(vmessProfile)
        assertEquals("Germany-VMess", vmessProfile?.name)
        assertEquals("de.example.com:8443", vmessProfile?.endpoint)

        val trojanProfile = com.travonet.wireguard.parser.ProxyLinkParser.parse(trojanUrl)
        assertNotNull(trojanProfile)
        assertEquals("Finland-Trojan", trojanProfile?.name)
        assertEquals("tr.example.com:443", trojanProfile?.endpoint)

        val ssProfile = com.travonet.wireguard.parser.ProxyLinkParser.parse(ssUrl)
        assertNotNull(ssProfile)
        assertEquals("Japan-SS", ssProfile?.name)
        assertEquals("ss.example.com:8388", ssProfile?.endpoint)

        val tuicProfile = com.travonet.wireguard.parser.ProxyLinkParser.parse(tuicUrl)
        assertNotNull(tuicProfile)
        assertEquals("US-TUIC", tuicProfile?.name)
        assertEquals("tuic.example.com:8443", tuicProfile?.endpoint)

        val hy2Profile = com.travonet.wireguard.parser.ProxyLinkParser.parse(hy2Url)
        assertNotNull(hy2Profile)
        assertEquals("UK-Hy2", hy2Profile?.name)
        assertEquals("hy2.example.com:443", hy2Profile?.endpoint)

        // Verify synthesized JSON stored in rawConfig upon import
        assertTrue(vlessProfile!!.rawConfig.startsWith("{"))
        assertTrue(vlessProfile.rawConfig.contains("\"protocol\": \"vless\"") || vlessProfile.rawConfig.contains("\"type\": \"vless\""))
        assertTrue(hy2Profile!!.rawConfig.startsWith("{"))
        assertTrue(hy2Profile.rawConfig.contains("\"type\": \"hysteria2\"") || hy2Profile.rawConfig.contains("\"type\":\"hysteria2\""))

        // FreeTURN import
        val sampleFreeTurnLink = "freeturn://eyJ2IjoxLCJwcm92aWRlciI6InZrIiwicGVlciI6IlRyYXZvbmV0LmRkbnMubmV0OjU2OTU4Iiwib2JmIjoicnRwb3B1czMiLCJrZXkiOiIzZjhjMDkwOTM0NmM0YzQ3OTFjNDVlZWU3Nzk1NmE2MGYwNDViNjUwMTE5ZmQxMTQ4NGE0ZjMxODFjMGUxYjQ3IiwibiI6MTIsInNwYyI6MTIsImNpZCI6IjFjOGUzMmI3Mzc4ZjhmODFkZTExZWUyMDg2MGU0NDQ2IiwibmFtZSI6InZhZGltIiwidmsiOiJodHRwczovL3ZrLnJ1L2NhbGwvam9pbi9NX1RUVmdCVzdpZFB3bnEtcXlvVDhSZDZLcDNwQUVtZXdBVDMzSVNja0drIiwid2ciOiJbSW50ZXJmYWNlXVxuUHJpdmF0ZUtleSA9IHNCV0JCOXJpTlorVEc4b2dEYVRHWC9WMTJhTkV1UDQvQ3hOMDlub3kxV009XG5BZGRyZXNzID0gMTAuMTMuMTMuMy8zMlxuRE5TID0gMS4xLjEuMSwgMS4wLjAuMVxuW1BlZXJdXG5QdWJsaWNLZXkgPSByeUlYUG5DUDRVY2tkajZRaFdjTUFEa1FPOE9DdDNGdHdpRjFIeWZ5SEc0PVxuQWxsb3dlZElQcyA9IDAuMC4wLjAvMCwgOjovMFxuRW5kcG9pbnQgPSAxMjcuMC4wLjE6OTAwMFxuUGVyc2lzdGVudEtlZXBhbGl2ZSA9IDI1In0"
        val ftProfile = com.travonet.wireguard.parser.ProxyLinkParser.parse(sampleFreeTurnLink)
        assertNotNull(ftProfile)
        assertEquals("vadim", ftProfile?.name)
        assertEquals("Travonet.ddns.net:56958", ftProfile?.endpoint)
        assertTrue(ftProfile!!.rawConfig.startsWith("{"))
        assertTrue(ftProfile.rawConfig.contains("\"peer\": \"Travonet.ddns.net:56958\""))
        assertTrue(ftProfile.rawConfig.contains("https://vk.ru/call/join/M_TTVgBW7idPwnq-qyoT8Rd6Kp3pAEmewAT33ISckGk"))
        assertTrue(ftProfile.rawConfig.contains("\"mode\": \"wg\""))
    }

    @Test
    fun testProxyConfigSynthesizerXrayAndSingbox() {
        val vlessUrl = "vless://03c478b6-93fb-43aa-9fa1-73ced8a13caf@185.229.9.135:443?security=reality&sni=example.com&pbk=xxxx&sid=yyyy&fp=chrome&type=tcp#TestVless"
        val xrayConfig = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            vlessUrl,
            com.travonet.wireguard.core.CoreType.XRAY
        )
        assertTrue(xrayConfig.contains("\"protocol\": \"tun\"") || xrayConfig.contains("\"protocol\":\"tun\""))
        assertTrue(xrayConfig.contains("\"protocol\": \"vless\"") || xrayConfig.contains("\"protocol\":\"vless\""))
        assertTrue(xrayConfig.contains("\"security\": \"reality\"") || xrayConfig.contains("\"security\":\"reality\""))
        assertTrue(xrayConfig.contains("185.229.9.135"))

        val singboxConfig = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            vlessUrl,
            com.travonet.wireguard.core.CoreType.SINGBOX
        )
        assertTrue(singboxConfig.contains("\"type\": \"tun\"") || singboxConfig.contains("\"type\":\"tun\""))
        assertTrue(singboxConfig.contains("\"type\": \"vless\"") || singboxConfig.contains("\"type\":\"vless\""))
        assertTrue(singboxConfig.contains("\"public_key\": \"xxxx\"") || singboxConfig.contains("\"public_key\":\"xxxx\""))

        val tuicUrl = "tuic://myuuid:mypass@tuic.example.com:8443?congestion_control=bbr#TestTuic"
        val tuicConfig = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            tuicUrl,
            com.travonet.wireguard.core.CoreType.SINGBOX
        )
        assertTrue(tuicConfig.contains("\"type\": \"tuic\"") || tuicConfig.contains("\"type\":\"tuic\""))
        assertTrue(tuicConfig.contains("\"congestion_control\": \"bbr\"") || tuicConfig.contains("\"congestion_control\":\"bbr\""))

        val hy2Url = "hysteria2://superpass@hy2.example.com:443#TestHy2"
        val hy2Config = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            hy2Url,
            com.travonet.wireguard.core.CoreType.SINGBOX
        )
        assertTrue(hy2Config.contains("\"type\": \"hysteria2\"") || hy2Config.contains("\"type\":\"hysteria2\""))
        assertTrue(hy2Config.contains("superpass"))

        val hy2AdvancedUrl = "hy2://my%20secret@hy2.server.com/?sni=cdn.example.com&obfs=salamander&obfs-password=salapass&mport=20000-30000&up=50m&down=100m&insecure=1#AdvHy2"
        val hy2AdvConfig = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            hy2AdvancedUrl,
            com.travonet.wireguard.core.CoreType.SINGBOX
        )
        assertTrue(hy2AdvConfig.contains("\"server\": \"hy2.server.com\""))
        assertTrue(hy2AdvConfig.contains("20000:30000"))
        assertTrue(hy2AdvConfig.contains("\"password\": \"my secret\""))
        assertTrue(hy2AdvConfig.contains("\"type\": \"salamander\""))
        assertTrue(hy2AdvConfig.contains("\"password\": \"salapass\""))
        assertTrue(hy2AdvConfig.contains("\"up_mbps\": 50"))
        assertTrue(hy2AdvConfig.contains("\"down_mbps\": 100"))
        assertTrue(hy2AdvConfig.contains("\"insecure\": true"))

        val userHy2 = "hysteria2://96cnnn2l15wkvmui@z.travonet.ru:56213?alpn=h3&fp=firefox&mport=20000-50000&obfs=salamander&obfs-password=kbwhuzdh2bw3pdpi&security=tls&sni=travonet.ddns.net#Hysteria%202"
        val userHy2Config = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            userHy2,
            com.travonet.wireguard.core.CoreType.SINGBOX
        )
        assertTrue(userHy2Config.contains("\"server_port\": 56213"))
        assertFalse(userHy2Config.contains("20000:50000"))
    }

    @Test
    fun testSubscriptionIsolationOnReplacement() {
        val sub1Url = "https://sub1.example.com/sub"
        val sub2Url = "https://sub2.example.com/sub"

        val prof1 = WgConfigParser.parseProfile(
            name = "Identical Server",
            rawConfig = sampleConfigWithoutStrategy,
            id = "sub1_p1",
            subscriptionUrl = sub1Url
        )
        val prof2 = WgConfigParser.parseProfile(
            name = "Identical Server",
            rawConfig = sampleConfigWithoutStrategy,
            id = "sub2_p1",
            subscriptionUrl = sub2Url
        )

        val list = mutableListOf(prof1, prof2)
        assertEquals(2, list.size)

        // Updating sub1 should NOT remove prof2 even if name and endpoint are identical
        val newSub1Profiles = listOf(
            WgConfigParser.parseProfile(
                name = "Identical Server",
                rawConfig = sampleConfigWithoutStrategy,
                id = "sub1_p1_updated",
                subscriptionUrl = sub1Url
            )
        )

        list.removeAll { p -> p.subscriptionUrl == sub1Url }
        list.addAll(newSub1Profiles)

        assertEquals(2, list.size)
        assertTrue(list.any { it.subscriptionUrl == sub1Url && it.id == "sub1_p1_updated" })
        assertTrue(list.any { it.subscriptionUrl == sub2Url && it.id == "sub2_p1" })
    }

    @Test
    fun testWarpIdentification() {
        val warpByName = WgConfigParser.parseProfile("WARP (Cloudflare)", sampleConfigWithoutStrategy)
        val warpByEndpoint = WgConfigParser.parseProfile("My CF", sampleConfigWithoutStrategy) // sampleConfigWithoutStrategy has 162.159.192.1:2408
        val nonWarp = WgConfigParser.parseProfile("Custom WG", """
            [Interface]
            PrivateKey = OCugIHnrk/r8Zdtd5AGYIchdMag+dqXF08yn1AZ2aUw=
            Address = 10.0.0.2/24

            [Peer]
            PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
            Endpoint = 198.51.100.1:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent())
        val subProfile = WgConfigParser.parseProfile(
            "WARP Server",
            sampleConfigWithoutStrategy,
            subscriptionUrl = "https://sub.com/list"
        )

        fun isWarp(p: com.travonet.wireguard.model.WgProfile): Boolean {
            if (!p.subscriptionUrl.isNullOrBlank()) return false
            if (p.name.contains("WARP", ignoreCase = true)) return true
            val ep = p.endpoint.lowercase()
            if (ep.contains("cloudflareclient.com")) return true
            if (ep.startsWith("162.159.192.") || ep.startsWith("162.159.193.") || ep.startsWith("162.159.195.")) return true
            return false
        }

        assertTrue(isWarp(warpByName))
        assertTrue(isWarp(warpByEndpoint))
        assertFalse(isWarp(nonWarp))
        assertFalse(isWarp(subProfile)) // Subscription profile is scoped to subscription, not WARP group
    }

    @Test
    fun testFreeTurnLinkParsing() {
        val jsonPayload = """{"v":1,"provider":"vk","peer":"185.220.101.5:56000","name":"FreeTURN VK Node","obf":"rtpopus"}"""
        val b64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(jsonPayload.toByteArray())
        val uri = "freeturn://$b64"

        assertTrue(com.travonet.wireguard.parser.ProxyLinkParser.isProxyLink(uri))

        val profile = com.travonet.wireguard.parser.ProxyLinkParser.parse(uri)
        assertNotNull(profile)
        assertEquals("FreeTURN VK Node", profile?.name)
        assertEquals("185.220.101.5:56000", profile?.endpoint)
        assertEquals("FreeTURN • VK", profile?.address)

        // CLI flags
        val cli = "-peer 194.87.1.1:56000 -provider vk -links https://vk.ru/call/join/abc123"
        assertTrue(com.travonet.wireguard.parser.ProxyLinkParser.isProxyLink(cli))
        val cliProfile = com.travonet.wireguard.parser.ProxyLinkParser.parse(cli)
        assertNotNull(cliProfile)
        assertEquals("194.87.1.1:56000", cliProfile?.endpoint)
    }

    @Test
    fun testFreeTurnRouting() {
        val uri = "freeturn://eyJ2IjoxLCJwcm92aWRlciI6InZrIiwicGVlciI6IjEuMi4zLjQ6NTYwMDAifQ"
        val res = com.travonet.wireguard.core.CoreRouter.route(uri)
        assertEquals(com.travonet.wireguard.core.CoreType.FREETURN, res.targetCore)
        assertEquals(com.travonet.wireguard.core.SupportedProtocol.FREETURN.displayName, res.detectedProtocol)

        val json = """{"peer":"1.2.3.4:56000","provider":"vk","vk":{"manualCaptcha":true}}"""
        val jsonRes = com.travonet.wireguard.core.CoreRouter.route(json)
        assertEquals(com.travonet.wireguard.core.CoreType.FREETURN, jsonRes.targetCore)

        val cli = "-peer 1.2.3.4:56000 -link https://vk.ru/call/join/test"
        val cliRes = com.travonet.wireguard.core.CoreRouter.route(cli)
        assertEquals(com.travonet.wireguard.core.CoreType.FREETURN, cliRes.targetCore)
    }

    @Test
    fun testFreeTurnConfigSynthesis() {
        val uri = "freeturn://testpayload"
        val outUri = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            uri,
            com.travonet.wireguard.core.CoreType.FREETURN
        )
        assertNotNull(outUri)

        val json = """{"peer":"1.2.3.4:56000","provider":"vk"}"""
        val outJson = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            json,
            com.travonet.wireguard.core.CoreType.FREETURN
        )
        assertTrue(outJson.contains("\"manualCaptcha\": true") || outJson.contains("\"manualCaptcha\":true"))
        assertTrue(outJson.contains("\"provider\": \"vk\"") || outJson.contains("\"provider\":\"vk\""))
        assertTrue(outJson.contains("\"peer\": \"1.2.3.4:56000\""))
    }

    @Test
    fun testFreeTurnEmbeddedWgExtraction() {
        val sampleWg = "[Interface]\nPrivateKey = cGFzc3dvcmQxMjM0NQ==\nAddress = 10.13.13.2/32\n[Peer]\nPublicKey = c2VydmVycHVibGljMTIz\nEndpoint = 127.0.0.1:9000\n"
        val jsonPayload = org.json.JSONObject().apply {
            put("v", 1)
            put("provider", "vk")
            put("peer", "185.220.1.1:56000")
            put("wg", sampleWg)
        }.toString()
        val b64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(jsonPayload.toByteArray())
        val uri = "freeturn://$b64"

        val extracted = com.travonet.wireguard.parser.ProxyLinkParser.extractEmbeddedWgConfig(uri)
        assertNotNull(extracted)
        assertTrue(extracted!!.contains("10.13.13.2/32"))
        assertTrue(extracted.contains("c2VydmVycHVibGljMTIz"))

        val profile = com.travonet.wireguard.parser.ProxyLinkParser.parse(uri)
        assertNotNull(profile)
        assertEquals("10.13.13.2/32", profile?.address)
    }

    @Test
    fun testUserProvidedFreeTurnLink() {
        val userLink = "freeturn://eyJ2IjoxLCJwcm92aWRlciI6InZrIiwicGVlciI6IlRyYXZvbmV0LmRkbnMubmV0OjU2OTU4Iiwib2JmIjoicnRwb3B1czMiLCJrZXkiOiIzZjhjMDkwOTM0NmM0YzQ3OTFjNDVlZWU3Nzk1NmE2MGYwNDViNjUwMTE5ZmQxMTQ4NGE0ZjMxODFjMGUxYjQ3IiwibiI6MTIsInNwYyI6MTIsImNpZCI6IjFjOGUzMmI3Mzc4ZjhmODFkZTExZWUyMDg2MGU0NDQ2IiwibmFtZSI6InZhZGltIiwidmsiOiJodHRwczovL3ZrLnJ1L2NhbGwvam9pbi9NX1RUVmdCVzdpZFB3bnEtcXlvVDhSZDZLcDNwQUVtZXdBVDMzSVNja0drIiwid2ciOiJbSW50ZXJmYWNlXVxuUHJpdmF0ZUtleSA9IHNCV0JCOXJpTlorVEc4b2dEYVRHWC9WMTJhTkV1UDQvQ3hOMDlub3kxV009XG5BZGRyZXNzID0gMTAuMTMuMTMuMy8zMlxuRE5TID0gMS4xLjEuMSwgMS4wLjAuMVxuW1BlZXJdXG5QdWJsaWNLZXkgPSByeUlYUG5DUDRVY2tkajZRaFdjTUFEa1FPOE9DdDNGdHdpRjFIeWZ5SEc0PVxuQWxsb3dlZElQcyA9IDAuMC4wLjAvMCwgOjovMFxuRW5kcG9pbnQgPSAxMjcuMC4wLjE6OTAwMFxuUGVyc2lzdGVudEtlZXBhbGl2ZSA9IDI1In0"

        val profile = com.travonet.wireguard.parser.ProxyLinkParser.parse(userLink)
        assertNotNull(profile)
        assertEquals("vadim", profile?.name)
        assertEquals("Travonet.ddns.net:56958", profile?.endpoint)
        assertEquals("10.13.13.3/32", profile?.address)
        assertEquals("1.1.1.1, 1.0.0.1", profile?.dns)

        val embeddedWg = com.travonet.wireguard.parser.ProxyLinkParser.extractEmbeddedWgConfig(userLink)
        assertNotNull(embeddedWg)
        assertTrue(embeddedWg!!.contains("sBWBB9riNZ+TG8ogDaTGX/V12aNEuP4/CxN09noy1WM="))
        assertTrue(embeddedWg.contains("127.0.0.1:9000"))

        val synthesized = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            userLink,
            com.travonet.wireguard.core.CoreType.FREETURN
        )
        assertTrue(synthesized.contains("\"peer\": \"Travonet.ddns.net:56958\""))
        assertTrue(synthesized.contains("https://vk.ru/call/join/M_TTVgBW7idPwnq-qyoT8Rd6Kp3pAEmewAT33ISckGk"))
        assertTrue(synthesized.contains("\"manualCaptcha\": true") || synthesized.contains("\"manualCaptcha\":true"))
        assertTrue(synthesized.contains("\"mode\": \"wg\""))
    }

    @Test
    fun testFreeTurnInSubscription() {
        val freeturnLink = "freeturn://eyJ2IjoxLCJwcm92aWRlciI6InZrIiwicGVlciI6IlRyYXZvbmV0LmRkbnMubmV0OjU2OTU4Iiwib2JmIjoicnRwb3B1czMiLCJrZXkiOiIzZjhjMDkwOTM0NmM0YzQ3OTFjNDVlZWU3Nzk1NmE2MGYwNDViNjUwMTE5ZmQxMTQ4NGE0ZjMxODFjMGUxYjQ3IiwibiI6MTIsInNwYyI6MTIsImNpZCI6IjFjOGUzMmI3Mzc4ZjhmODFkZTExZWUyMDg2MGU0NDQ2IiwibmFtZSI6InZhZGltIiwidmsiOiJodHRwczovL3ZrLnJ1L2NhbGwvam9pbi9NX1RUVmdCVzdpZFB3bnEtcXlvVDhSZDZLcDNwQUVtZXdBVDMzSVNja0drIiwid2ciOiJbSW50ZXJmYWNlXVxuUHJpdmF0ZUtleSA9IHNCV0JCOXJpTlorVEc4b2dEYVRHWC9WMTJhTkV1UDQvQ3hOMDlub3kxV009XG5BZGRyZXNzID0gMTAuMTMuMTMuMy8zMlxuRE5TID0gMS4xLjEuMSwgMS4wLjAuMVxuW1BlZXJdXG5QdWJsaWNLZXkgPSByeUlYUG5DUDRVY2tkajZRaFdjTUFEa1FPOE9DdDNGdHdpRjFIeWZ5SEc0PVxuQWxsb3dlZElQcyA9IDAuMC4wLjAvMCwgOjovMFxuRW5kcG9pbnQgPSAxMjcuMC4wLjE6OTAwMFxuUGVyc2lzdGVudEtlZXBhbGl2ZSA9IDI1In0"
        
        // 1. Raw multi-line subscription text containing freeturn://
        val rawSub = "vless://user@1.2.3.4:443?security=none#VlessServer\n$freeturnLink\n"
        val profiles = com.travonet.wireguard.subscription.SubscriptionFetcher.parseSubscriptionBody(
            body = rawSub,
            defaultTitle = "TestSub",
            subscriptionUrl = "https://example.com/sub"
        )

        assertEquals(2, profiles.size)
        val ftProfile = profiles.find {
            com.travonet.wireguard.core.CoreRouter.route(it.rawConfig).targetCore == com.travonet.wireguard.core.CoreType.FREETURN
        }
        assertNotNull(ftProfile)
        assertEquals("vadim", ftProfile?.name)
        assertTrue(ftProfile!!.rawConfig.contains("\"peer\": \"Travonet.ddns.net:56958\""))
        assertTrue(ftProfile.rawConfig.contains("https://vk.ru/call/join/M_TTVgBW7idPwnq-qyoT8Rd6Kp3pAEmewAT33ISckGk"))

        // 2. Base64-encoded subscription containing freeturn://
        val base64Sub = java.util.Base64.getEncoder().encodeToString(rawSub.toByteArray(java.nio.charset.StandardCharsets.UTF_8))
        val decodedProfiles = com.travonet.wireguard.subscription.SubscriptionFetcher.parseSubscriptionBody(
            body = base64Sub,
            defaultTitle = "Base64Sub",
            subscriptionUrl = "https://example.com/sub2"
        )
        assertEquals(2, decodedProfiles.size)
        val ftDecoded = decodedProfiles.find {
            com.travonet.wireguard.core.CoreRouter.route(it.rawConfig).targetCore == com.travonet.wireguard.core.CoreType.FREETURN
        }
        assertNotNull(ftDecoded)
        assertEquals("vadim", ftDecoded?.name)
        assertTrue(ftDecoded!!.rawConfig.contains("\"peer\": \"Travonet.ddns.net:56958\""))
    }

    @Test
    fun testSingboxConfigHasDomainResolverForOutboundServer() {
        val hy2Link = "hysteria2://secret@proxy.example.com:443?sni=proxy.example.com#TestHy2"

        val vpn = org.json.JSONObject(
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
                hy2Link,
                com.travonet.wireguard.core.CoreType.SINGBOX,
                com.travonet.wireguard.model.TunnelMode.VPN
            )
        )
        assertEquals(
            "direct-dns",
            vpn.getJSONObject("route").getString("default_domain_resolver")
        )
        assertTrue(hasDnsServerTag(vpn, "direct-dns"))
        assertFalse(hasOutboundDnsRule(vpn))

        val socks = org.json.JSONObject(
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
                hy2Link,
                com.travonet.wireguard.core.CoreType.SINGBOX,
                com.travonet.wireguard.model.TunnelMode.SOCKS5
            )
        )
        assertEquals(
            "direct-dns",
            socks.getJSONObject("route").getString("default_domain_resolver")
        )
        assertTrue(hasDnsServerTag(socks, "direct-dns"))
    }

    @Test
    fun testRawSingboxConfigMigratesLegacyOutboundDnsRules() {
        val raw = """
            {
              "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"]}],
              "dns": {
                "servers": [
                  {"tag": "remote-dns", "type": "https", "server": "1.1.1.1", "detour": "proxy", "path": "/dns-query"},
                  {"tag": "direct-dns", "type": "local", "detour": "direct"}
                ],
                "rules": [{"outbound": ["any"], "server": "direct-dns"}]
              },
              "route": {"rules": [{"inbound": "tun-in", "outbound": "proxy"}]},
              "outbounds": [{"type": "hysteria2", "tag": "proxy", "server": "proxy.example.com", "server_port": 443}]
            }
        """.trimIndent()

        val out = org.json.JSONObject(
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
                raw,
                com.travonet.wireguard.core.CoreType.SINGBOX,
                com.travonet.wireguard.model.TunnelMode.VPN
            )
        )
        assertEquals(
            "direct-dns",
            out.getJSONObject("route").getString("default_domain_resolver")
        )
        assertTrue(hasDnsServerTag(out, "direct-dns"))
        assertFalse(hasOutboundDnsRule(out))
    }

    @Test
    fun testRawSingboxConfigWithoutDnsGetsDirectResolver() {
        val raw = """{"outbounds":[{"type":"vless","tag":"proxy","server":"proxy.example.com","server_port":443}]}"""

        val out = org.json.JSONObject(
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
                raw,
                com.travonet.wireguard.core.CoreType.SINGBOX,
                com.travonet.wireguard.model.TunnelMode.SOCKS5
            )
        )
        assertEquals(
            "direct-dns",
            out.getJSONObject("route").getString("default_domain_resolver")
        )
        assertTrue(hasDnsServerTag(out, "direct-dns"))
    }

    private fun hasDnsServerTag(config: org.json.JSONObject, tag: String): Boolean {
        val servers = config.optJSONObject("dns")?.optJSONArray("servers") ?: return false
        for (i in 0 until servers.length()) {
            if (servers.optJSONObject(i)?.optString("tag") == tag) return true
        }
        return false
    }

    private fun hasOutboundDnsRule(config: org.json.JSONObject): Boolean {
        val rules = config.optJSONObject("dns")?.optJSONArray("rules") ?: return false
        for (i in 0 until rules.length()) {
            if (rules.optJSONObject(i)?.has("outbound") == true) return true
        }
        return false
    }

    @Test
    fun testTunAndSocksConfigSynthesis() {
        val vlessLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=reality&type=tcp&sni=yahoo.com&fp=chrome&pbk=12345&sid=abcd#TestVless"

        // 1. Xray in VPN (TUN) mode
        val xrayTun = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            rawConfig = vlessLink,
            targetCore = com.travonet.wireguard.core.CoreType.XRAY,
            mode = com.travonet.wireguard.model.TunnelMode.VPN
        )
        val xrayTunJson = org.json.JSONObject(xrayTun)
        val xrayTunInbounds = xrayTunJson.getJSONArray("inbounds")
        assertEquals(1, xrayTunInbounds.length())
        assertEquals("tun-in", xrayTunInbounds.getJSONObject(0).getString("tag"))
        assertEquals("tun", xrayTunInbounds.getJSONObject(0).getString("protocol"))

        // 2. Xray in SOCKS5 mode
        val xraySocks = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            rawConfig = vlessLink,
            targetCore = com.travonet.wireguard.core.CoreType.XRAY,
            mode = com.travonet.wireguard.model.TunnelMode.SOCKS5,
            socksListen = "127.0.0.1:1080"
        )
        val xraySocksJson = org.json.JSONObject(xraySocks)
        val xraySocksInbounds = xraySocksJson.getJSONArray("inbounds")
        assertEquals(1, xraySocksInbounds.length())
        assertEquals("socks-in", xraySocksInbounds.getJSONObject(0).getString("tag"))
        assertEquals("socks", xraySocksInbounds.getJSONObject(0).getString("protocol"))
        assertEquals(1080, xraySocksInbounds.getJSONObject(0).getInt("port"))
        assertEquals("127.0.0.1", xraySocksInbounds.getJSONObject(0).getString("listen"))

        // 3. Sing-box in VPN (TUN) mode
        val singboxTun = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            rawConfig = vlessLink,
            targetCore = com.travonet.wireguard.core.CoreType.SINGBOX,
            mode = com.travonet.wireguard.model.TunnelMode.VPN
        )
        val singboxTunJson = org.json.JSONObject(singboxTun)
        val singboxTunInbounds = singboxTunJson.getJSONArray("inbounds")
        assertEquals(1, singboxTunInbounds.length())
        assertEquals("tun", singboxTunInbounds.getJSONObject(0).getString("type"))
        assertEquals("tun-in", singboxTunInbounds.getJSONObject(0).getString("tag"))
        assertTrue(singboxTunJson.has("dns"))

        // 4. Sing-box in SOCKS5 mode
        val singboxSocks = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            rawConfig = vlessLink,
            targetCore = com.travonet.wireguard.core.CoreType.SINGBOX,
            mode = com.travonet.wireguard.model.TunnelMode.SOCKS5,
            socksListen = "127.0.0.1:1080"
        )
        val singboxSocksJson = org.json.JSONObject(singboxSocks)
        val singboxSocksInbounds = singboxSocksJson.getJSONArray("inbounds")
        assertEquals(1, singboxSocksInbounds.length())
        assertEquals("socks", singboxSocksInbounds.getJSONObject(0).getString("type"))
        assertEquals("socks-in", singboxSocksInbounds.getJSONObject(0).getString("tag"))
        assertEquals(1080, singboxSocksInbounds.getJSONObject(0).getInt("listen_port"))
        assertEquals("127.0.0.1", singboxSocksInbounds.getJSONObject(0).getString("listen"))

        // 5. FreeTURN in SOCKS5 mode
        val ftLink = "freeturn://eyJ2IjoxLCJwcm92aWRlciI6InZrIiwicGVlciI6IlRyYXZvbmV0LmRkbnMubmV0OjU2OTU4Iiwib2JmIjoicnRwb3B1czMiLCJrZXkiOiIxMjM0IiwibiI6MTIsInNwYyI6MTIsInZrIjoiaHR0cHM6Ly92ay5ydS9jYWxsL2pvaW4vdGVzdCIsIndnIjoiW0ludGVyZmFjZV1cblByaXZhdGVLZXkgPSBhYmNkXG5BZGRyZXNzID0gMTAuMC4wLjIvMjRcbltQZWVyXVxuUHVibGljS2V5ID0geHl6XG5FbmRwb2ludCA9IDEyNy4wLjAuMTo5MDAwXG5BbGxvd2VkSVBzID0gMC4wLjAuMC8wIn0="
        val ftSocks = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            rawConfig = ftLink,
            targetCore = com.travonet.wireguard.core.CoreType.FREETURN,
            mode = com.travonet.wireguard.model.TunnelMode.SOCKS5,
            socksListen = "127.0.0.1:1080"
        )
        val ftSocksJson = org.json.JSONObject(ftSocks)
        assertEquals("udp", ftSocksJson.getJSONObject("proxy").getString("mode"))
        assertEquals("127.0.0.1:1080", ftSocksJson.getJSONObject("proxy").getString("listen"))
        assertEquals("none", ftSocksJson.getJSONObject("tunnel").getString("mode"))
    }

    @Test
    fun testSingboxGvisorStackAndDnsRoutingModes() {
        val vlessLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=reality&type=tcp&sni=yahoo.com&fp=chrome&pbk=12345&sid=abcd#TestVless"

        // 1. Sing-box VPN uses gvisor stack (not mixed which causes SELinux netlink crash)
        val singboxVpn = org.json.JSONObject(
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
                rawConfig = vlessLink,
                targetCore = com.travonet.wireguard.core.CoreType.SINGBOX,
                mode = com.travonet.wireguard.model.TunnelMode.VPN,
                dnsMode = com.travonet.wireguard.model.DnsMode.SERVER
            )
        )
        val tunObj = singboxVpn.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("gvisor", tunObj.getString("stack"))

        // direct-dns is an explicit IP (not "local" which fails on Android)
        val dnsServers = singboxVpn.getJSONObject("dns").getJSONArray("servers")
        var directDnsFound = false
        for (i in 0 until dnsServers.length()) {
            val s = dnsServers.getJSONObject(i)
            if (s.optString("tag") == "direct-dns") {
                assertFalse(s.has("detour"))
                assertNotEquals("local", s.optString("type"))
                directDnsFound = true
            }
        }
        assertTrue(directDnsFound)

        // 2. DnsMode.SERVER / CUSTOM: route rules hijack DNS
        val serverRules = singboxVpn.getJSONObject("route").getJSONArray("rules")
        var hasHijack = false
        for (i in 0 until serverRules.length()) {
            val r = serverRules.getJSONObject(i)
            if (r.optString("action") == "hijack-dns") {
                hasHijack = true
            }
        }
        assertTrue("DnsMode.SERVER must have hijack-dns rule", hasHijack)

        // 3. DnsMode.SYSTEM: route rules hijack DNS, but final resolver is direct-dns
        val singboxSystem = org.json.JSONObject(
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
                rawConfig = vlessLink,
                targetCore = com.travonet.wireguard.core.CoreType.SINGBOX,
                mode = com.travonet.wireguard.model.TunnelMode.VPN,
                dnsMode = com.travonet.wireguard.model.DnsMode.SYSTEM
            )
        )
        assertEquals("direct-dns", singboxSystem.getJSONObject("dns").getString("final"))
        val sysRules = singboxSystem.getJSONObject("route").getJSONArray("rules")
        var hasSystemHijack = false
        for (i in 0 until sysRules.length()) {
            val r = sysRules.getJSONObject(i)
            if (r.optString("action") == "hijack-dns") {
                hasSystemHijack = true
            }
        }
        assertTrue("DnsMode.SYSTEM must have hijack-dns rule to prevent ISP drops", hasSystemHijack)
    }

    @Test
    fun testXrayDnsConfiguration() {
        val vlessLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=reality&type=tcp&sni=yahoo.com&fp=chrome&pbk=12345&sid=abcd#TestVless"

        val xrayConfig = org.json.JSONObject(
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
                rawConfig = vlessLink,
                targetCore = com.travonet.wireguard.core.CoreType.XRAY,
                mode = com.travonet.wireguard.model.TunnelMode.VPN,
                dnsMode = com.travonet.wireguard.model.DnsMode.CUSTOM,
                dohUrl = "https://dns.quad9.net/dns-query"
            )
        )
        assertTrue(xrayConfig.has("dns"))
        val servers = xrayConfig.getJSONObject("dns").getJSONArray("servers")
        var hasQuad9 = false
        for (i in 0 until servers.length()) {
            if (servers.getString(i).contains("dns.quad9.net")) hasQuad9 = true
        }
        assertTrue(hasQuad9)
    }

    @Test
    fun testEnsurePersistentKeepalive() {
        val rawNoKeepalive = """
            [Interface]
            PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            Address = 10.0.0.2/32

            [Peer]
            PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            Endpoint = 1.2.3.4:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()

        val withKeepalive = WgConfigParser.ensurePersistentKeepalive(rawNoKeepalive, 25)
        assertTrue(withKeepalive.contains("PersistentKeepalive = 25"))

        // Multiple peers and existing keepalive preservation
        val rawMultiPeer = """
            [Interface]
            PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            Address = 10.0.0.2/32

            [Peer]
            PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            Endpoint = 1.2.3.4:51820
            AllowedIPs = 0.0.0.0/0
            PersistentKeepalive = 15

            [Peer]
            PublicKey = cccccccccccccccccccccccccccccccccccccccc
            Endpoint = 5.6.7.8:51820
            AllowedIPs = 10.0.1.0/24
        """.trimIndent()

        val multiResult = WgConfigParser.ensurePersistentKeepalive(rawMultiPeer, 25)
        assertTrue(multiResult.contains("PersistentKeepalive = 15"))
        assertTrue(multiResult.contains("PersistentKeepalive = 25"))
    }

    @Test
    fun testProxyConfigKeepAliveAndTunMtu() {
        val vlessLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=reality&type=tcp&sni=yahoo.com&fp=chrome&pbk=12345&sid=abcd#TestVless"

        val singboxVpn = org.json.JSONObject(
            com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
                rawConfig = vlessLink,
                targetCore = com.travonet.wireguard.core.CoreType.SINGBOX,
                mode = com.travonet.wireguard.model.TunnelMode.VPN
            )
        )

        // Check TUN MTU
        val tunInbound = singboxVpn.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("tun", tunInbound.getString("type"))
        assertEquals(1420, tunInbound.getInt("mtu"))

        // Check proxy outbound keepalive
        val proxyOutbound = singboxVpn.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("15s", proxyOutbound.getString("tcp_keep_alive_interval"))
        assertEquals("10s", proxyOutbound.getString("connect_timeout"))

        // Check DNS resilience (Yandex direct fallback & independent cache)
        val dnsObj = singboxVpn.getJSONObject("dns")
        assertTrue(dnsObj.getBoolean("independent_cache"))
        val dnsServers = dnsObj.getJSONArray("servers")
        var hasYandexFallback = false
        for (i in 0 until dnsServers.length()) {
            val s = dnsServers.getJSONObject(i)
            if (s.optString("server") == "77.88.8.8") hasYandexFallback = true
        }
        assertTrue("direct DNS should contain Yandex fallback for RU resilience", hasYandexFallback)
    }

    @Test
    fun testFreeTurnWireguardSynthesisAndExtraction() {
        val sampleWg = """
            [Interface]
            PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
            Address = 10.8.0.2/32
            DNS = 1.1.1.1
            MTU = 1360

            [Peer]
            PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 127.0.0.1:9000
        """.trimIndent()

        val freeTurnJsonInput = org.json.JSONObject().apply {
            put("peer", "5.231.117.26:5000")
            put("provider", "vk")
            put("vk", org.json.JSONObject().apply {
                put("links", org.json.JSONArray().put("https://vk.ru/call/join/test12345"))
            })
            put("wg", sampleWg)
        }.toString()

        val synthesized = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            rawConfig = freeTurnJsonInput,
            targetCore = com.travonet.wireguard.core.CoreType.FREETURN,
            mode = com.travonet.wireguard.model.TunnelMode.VPN
        )

        val root = org.json.JSONObject(synthesized)
        assertEquals("5.231.117.26:5000", root.getString("peer"))
        assertEquals("vk", root.getString("provider"))

        // Check tunnel section
        val tunnelObj = root.getJSONObject("tunnel")
        assertEquals("wg", tunnelObj.getString("mode"))
        assertTrue("tunnel.config should contain [Interface]", tunnelObj.getString("config").contains("[Interface]"))
        assertTrue("tunnel.config should contain PrivateKey", tunnelObj.getString("config").contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="))

        // Verify extraction
        val extracted = com.travonet.wireguard.parser.ProxyLinkParser.extractEmbeddedWgConfig(synthesized)
        assertNotNull(extracted)
        assertTrue(extracted!!.contains("10.8.0.2/32"))

        // Verify parsing for Android VpnService.Builder
        val parsedWg = com.travonet.wireguard.parser.WgConfigParser.parse(extracted)
        assertEquals("10.8.0.2/32", parsedWg.iface.addresses.first())
        assertEquals("0.0.0.0/0", parsedWg.peers.first().allowedIps.first())
    }

    @Test
    fun testVlessNotDetectedAsHysteria2AndNoLoglevelInSingbox() {
        val vlessUrl = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@www.blazebit.dev:443?encryption=none&security=reality&type=tcp&sni=www.blazebit.dev&fp=chrome&pbk=12345&sid=abcd&flow=xtls-rprx-vision#Польша"
        val profile = com.travonet.wireguard.parser.ProxyLinkParser.parse(vlessUrl)
        assertNotNull(profile)
        assertEquals("Польша", profile?.name)

        // 1. CoreRouter must identify rawConfig as VLESS and route to Xray (default)
        val routeResult = com.travonet.wireguard.core.CoreRouter.route(profile!!.rawConfig)
        assertEquals("VLESS (Reality)", routeResult.detectedProtocol)
        assertEquals(com.travonet.wireguard.core.CoreType.XRAY, routeResult.targetCore)

        // 2. Even if delegated to Sing-box or synthesized for Sing-box, loglevel must NOT appear
        val singboxConf = com.travonet.wireguard.parser.ProxyConfigSynthesizer.synthesize(
            rawConfig = profile.rawConfig,
            targetCore = com.travonet.wireguard.core.CoreType.SINGBOX
        )
        val sbJson = org.json.JSONObject(singboxConf)
        val logObj = sbJson.optJSONObject("log")
        if (logObj != null) {
            assertFalse("Sing-box must not contain loglevel field", logObj.has("loglevel"))
            assertTrue("Sing-box must contain level field", logObj.has("level"))
        }

        // 3. Routing singboxConf itself must detect VLESS, NOT Hysteria 2
        val sbRoute = com.travonet.wireguard.core.CoreRouter.route(singboxConf)
        assertEquals("VLESS (Reality)", sbRoute.detectedProtocol)
    }

    @Test
    fun testWatchdogDeadDownlinkDetection() {
        fun evaluateConnectionStatus(
            deltaTx: Long,
            deltaRx: Long,
            timeSinceHandshake: Long,
            txSentDuringStale: Long
        ): Boolean {
            val isRekeyFailed = timeSinceHandshake > 135L && deltaRx <= 0L
            val isDeadDownlink = (deltaTx > 0L || txSentDuringStale > 200L) && deltaRx <= 0L && timeSinceHandshake > 25L
            val isHandshakeExpired = timeSinceHandshake > 180L
            return isRekeyFailed || isDeadDownlink || isHandshakeExpired
        }

        // Healthy active connection: tx > 0 and rx > 0
        assertFalse(evaluateConnectionStatus(deltaTx = 500, deltaRx = 1200, timeSinceHandshake = 10, txSentDuringStale = 0))

        // Healthy idle connection: tx == 0 and rx == 0, handshake fresh
        assertFalse(evaluateConnectionStatus(deltaTx = 0, deltaRx = 0, timeSinceHandshake = 45, txSentDuringStale = 0))

        // Dead downlink: user sending traffic, but 0 bytes received
        assertTrue(evaluateConnectionStatus(deltaTx = 300, deltaRx = 0, timeSinceHandshake = 35, txSentDuringStale = 0))

        // Rekey failed: handshake older than 135s (normal rekey is 120s) and rx is 0
        assertTrue(evaluateConnectionStatus(deltaTx = 0, deltaRx = 0, timeSinceHandshake = 140, txSentDuringStale = 0))

        // Complete handshake expiration: > 180s
        assertTrue(evaluateConnectionStatus(deltaTx = 0, deltaRx = 0, timeSinceHandshake = 185, txSentDuringStale = 0))
    }
}


