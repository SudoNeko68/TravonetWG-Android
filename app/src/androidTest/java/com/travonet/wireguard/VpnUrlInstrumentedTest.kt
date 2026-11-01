package com.travonet.wireguard

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.travonet.wireguard.parser.WgConfigParser
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.travonet.backend.GoBackend
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Base64
import java.util.zip.DeflaterOutputStream

@RunWith(AndroidJUnit4::class)
class VpnUrlInstrumentedTest {

    private fun createQtCompressedVpnUrl(json: String): String {
        val bos = ByteArrayOutputStream()
        val deflater = DeflaterOutputStream(bos)
        deflater.write(json.toByteArray(Charsets.UTF_8))
        deflater.finish()
        deflater.close()
        val compressedBytes = bos.toByteArray()

        // Qt qCompress format: 4 bytes big endian uncompressed length + zlib compressed stream
        val qtBuffer = ByteBuffer.allocate(4 + compressedBytes.size)
        qtBuffer.order(ByteOrder.BIG_ENDIAN)
        qtBuffer.putInt(json.toByteArray(Charsets.UTF_8).size)
        qtBuffer.put(compressedBytes)

        val b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(qtBuffer.array())
        return "vpn://$b64"
    }

    private fun createPlainJsonVpnUrl(json: String): String {
        val b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray(Charsets.UTF_8))
        return "vpn://$b64"
    }

    @Test
    fun testParseVpnUrlViaGoBackend_QtCompressed() {
        val sampleJson = """{
            "hostName": "qt-server.example.com",
            "description": "Amnezia AWG Server",
            "containers": [
                {
                    "container": "amnezia-awg",
                    "awg": {
                        "last_config": "{\"client_priv_key\":\"ccccccccccccccccccccccccccccccccccccccccccc=\",\"server_pub_key\":\"ddddddddddddddddddddddddddddddddddddddddddd=\",\"client_ip\":\"10.7.0.2\",\"port\":51820,\"Jc\":3,\"Jmin\":40,\"Jmax\":80,\"S1\":50,\"S2\":100,\"H1\":\"111\",\"H2\":\"222\",\"H3\":\"333\",\"H4\":\"444\"}"
                    }
                }
            ]
        }""".trimIndent()

        val vpnUrl = createQtCompressedVpnUrl(sampleJson)

        // 1. Direct call to native GoBackend
        val jsonResult = GoBackend.wgParseVPNURL(vpnUrl)
        assertNotNull("GoBackend.wgParseVPNURL should return a result", jsonResult)
        assertFalse("Result should not be an error: $jsonResult", jsonResult!!.startsWith("ERROR:"))

        val obj = JSONObject(jsonResult)
        assertEquals("Amnezia AWG Server", obj.getString("name"))
        val config = obj.getString("config")

        assertTrue("Config should contain PrivateKey", config.contains("PrivateKey = ccccccccccccccccccccccccccccccccccccccccccc="))
        assertTrue("Config should contain PublicKey", config.contains("PublicKey = ddddddddddddddddddddddddddddddddddddddddddd="))
        assertTrue("Config should contain Endpoint", config.contains("Endpoint = qt-server.example.com:51820"))
        assertTrue("Config should contain Jc", config.contains("Jc = 3"))
        assertTrue("Config should contain H4", config.contains("H4 = 444"))

        // 2. High-level call through WgConfigParser
        val profile = WgConfigParser.parseProfile("vpn://import", vpnUrl)
        assertEquals("Amnezia AWG Server", profile.name)
        assertEquals("qt-server.example.com:51820", profile.endpoint)
        assertTrue(profile.rawConfig.contains("[Interface]"))
        assertTrue(profile.rawConfig.contains("Jc = 3"))
    }

    @Test
    fun testParseVpnUrlViaGoBackend_PlainJson() {
        val sampleJson = """{
            "hostName": "plain-server.example.com",
            "description": "Plain AWG Config",
            "containers": [
                {
                    "container": "amnezia-awg",
                    "awg": {
                        "last_config": "[Interface]\nPrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nAddress = 10.8.0.2/24\nDNS = 1.1.1.1\nJc = 4\nJmin = 50\nJmax = 100\nS1 = 15\nS2 = 20\nH1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890\n\n[Peer]\nPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\nEndpoint = 198.51.100.1:29835\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
                    }
                }
            ]
        }""".trimIndent()

        val vpnUrl = createPlainJsonVpnUrl(sampleJson)

        val profile = WgConfigParser.parseProfile("", vpnUrl)
        assertEquals("Plain AWG Config", profile.name)
        assertEquals("198.51.100.1:29835", profile.endpoint)
        assertEquals("10.8.0.2/24", profile.address)
        assertTrue(profile.rawConfig.contains("Jc = 4"))
        assertTrue(profile.rawConfig.contains("H1 = 1234567"))
    }

    @Test
    fun testParseVpnUrl_InvalidUrl() {
        val result = GoBackend.wgParseVPNURL("vpn://this_is_not_valid_payload")
        assertNotNull(result)
        assertTrue("Invalid URL should return ERROR", result!!.startsWith("ERROR:"))
    }
}
