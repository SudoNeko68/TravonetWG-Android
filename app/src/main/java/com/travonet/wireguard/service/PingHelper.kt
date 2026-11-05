package com.travonet.wireguard.service

import com.travonet.wireguard.model.EvasionStrategy
import com.travonet.wireguard.model.TunnelMode
import com.travonet.wireguard.model.TunnelStatus
import com.travonet.wireguard.model.WgProfile
import com.travonet.wireguard.parser.WgConfigParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.travonet.backend.GoBackend
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL

data class PingResult(
    val udpPingMs: Long? = null,
    val udpError: Boolean = false,
    val httpPingMs: Long? = null,
    val httpError: Boolean = false,
    val isTesting: Boolean = false
)

object PingHelper {
    private const val TARGET_HOST = "connectivitycheck.gstatic.com"
    private const val HTTP_PATH = "/generate_204"

    fun extractHost(endpoint: String): String {
        val trimmed = endpoint.trim()
        return when {
            trimmed.startsWith("[") -> trimmed.substringAfter("[").substringBefore("]")
            trimmed.contains(":") -> trimmed.substringBefore(":")
            else -> trimmed
        }
    }

    /**
     * Пинг без рукопожатия (UDP/транспортная доступность хоста).
     * Запускает системный ping до хоста эндпоинта.
     */
    suspend fun pingUdpHost(endpoint: String, timeoutSec: Int = 2): Long? = withContext(Dispatchers.IO) {
        val host = extractHost(endpoint)
        if (host.isBlank()) return@withContext null
        try {
            val process = Runtime.getRuntime().exec(
                arrayOf("/system/bin/ping", "-c", "1", "-w", timeoutSec.toString(), host)
            )
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            var timeMs: Long? = null
            val timeRegex = Regex("time=([0-9.]+)\\s*ms")
            val rttRegex = Regex("rtt min/avg/max/mdev = [0-9.]+/([0-9.]+)")
            while (reader.readLine().also { line = it } != null) {
                val l = line ?: continue
                val m = timeRegex.find(l) ?: rttRegex.find(l)
                if (m != null) {
                    timeMs = m.groupValues[1].toDoubleOrNull()?.toLong()
                }
            }
            process.waitFor()
            if (process.exitValue() == 0 && timeMs != null) timeMs else null
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Пинг с рукопожатием (HTTP generate_204 через WireGuard + SOCKS5).
     * Если туннель уже подключен в приложении, использует текущий активный канал.
     * Если туннель выключен, запускает временный локальный SOCKS5 на свободном порту,
     * выполняет запрос к gstatic.com/generate_204 и сразу останавливает SOCKS5.
     */
    suspend fun pingHttp204(
        profile: WgProfile,
        strategy: EvasionStrategy
    ): Long? = withContext(Dispatchers.IO) {
        val currentStatus = TunnelManager.state.value

        // Если туннель уже подключен в приложении
        if (currentStatus.status == TunnelStatus.CONNECTED) {
            return@withContext pingConnectedTunnel(currentStatus.mode)
        }

        val route = com.travonet.wireguard.core.CoreRouter.route(profile.rawConfig)
        if (route.targetCore != com.travonet.wireguard.core.CoreType.TRAVONET_WG) {
            return@withContext null
        }

        // Если туннель выключен: поднимаем временный изолированный SOCKS5 без создания VPN
        val freePort = try {
            ServerSocket(0).use { it.localPort }
        } catch (_: Exception) {
            11080
        }

        val preparedConfig = WgConfigParser.prepareConfigForLaunch(profile, strategy)
        val handle = try {
            GoBackend.wgStartSocks5("127.0.0.1:$freePort", preparedConfig)
        } catch (_: Exception) {
            -1
        }
        if (handle < 0) return@withContext null

        try {
            // Даём ядру 150мс на запуск слушателя и первичный handshake
            delay(150)
            var latency = probeSocks5Http204("127.0.0.1", freePort, timeoutMs = 3500)
            if (latency == null) {
                delay(200)
                latency = probeSocks5Http204("127.0.0.1", freePort, timeoutMs = 3500)
            }
            latency
        } finally {
            try {
                GoBackend.wgStopSocks5(handle)
            } catch (_: Exception) {}
        }
    }

    private fun pingConnectedTunnel(mode: TunnelMode): Long? {
        return if (mode == TunnelMode.SOCKS5 && TunnelManager.socksHandle >= 0) {
            probeSocks5Http204("127.0.0.1", 1080, timeoutMs = 4000)
        } else {
            // VPN (TUN) активен — проверяем прямой запрос через системную маршрутизацию
            probeDirectHttp204()
        }
    }

    private fun probeDirectHttp204(): Long? {
        val start = System.currentTimeMillis()
        return try {
            val url = URL("https://$TARGET_HOST$HTTP_PATH")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            conn.connect()
            val code = conn.responseCode
            val elapsed = System.currentTimeMillis() - start
            conn.disconnect()
            if (code in 200..299 || code == 302) elapsed else null
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Выполняет прямой SOCKS5 запрос с удалённым DNS-резолвингом (ATYP 0x03).
     * Это гарантирует обход локального DNS-спуфинга оператора и не зависит от
     * политик Android cleartext.
     */
    private fun probeSocks5Http204(proxyHost: String, proxyPort: Int, timeoutMs: Int): Long? {
        val start = System.currentTimeMillis()
        val socket = Socket()
        return try {
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)
            val out = socket.getOutputStream()
            val input = socket.getInputStream()

            // 1. SOCKS5 Greeting: VER=5, NMETHODS=1, METHOD=0 (No Auth)
            out.write(byteArrayOf(0x05, 0x01, 0x00))
            out.flush()

            val greetResp = ByteArray(2)
            var read = input.read(greetResp)
            if (read < 2 || greetResp[0] != 0x05.toByte() || greetResp[1] != 0x00.toByte()) {
                return null
            }

            // 2. SOCKS5 Connect: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (DOMAIN)
            val hostBytes = TARGET_HOST.toByteArray(Charsets.US_ASCII)
            val req = ByteArrayOutputStream()
            req.write(byteArrayOf(0x05, 0x01, 0x00, 0x03, hostBytes.size.toByte()))
            req.write(hostBytes)
            // Port 80 (0x00, 0x50)
            req.write(byteArrayOf(0x00, 0x50))
            out.write(req.toByteArray())
            out.flush()

            // SOCKS5 Connect Response: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
            val connResp = ByteArray(4)
            read = input.read(connResp)
            if (read < 4 || connResp[1] != 0x00.toByte()) {
                return null
            }

            val atyp = connResp[3].toInt()
            val skipLen = when (atyp) {
                0x01 -> 4 + 2 // IPv4 + port
                0x03 -> {
                    val domainLen = input.read()
                    domainLen + 2 // domain + port
                }
                0x04 -> 16 + 2 // IPv6 + port
                else -> 6
            }
            val skipBuf = ByteArray(skipLen)
            input.read(skipBuf)

            // 3. Send HTTP request
            val httpReq = "GET $HTTP_PATH HTTP/1.1\r\nHost: $TARGET_HOST\r\nConnection: close\r\nUser-Agent: TravonetVPN/Ping\r\n\r\n"
            out.write(httpReq.toByteArray(Charsets.US_ASCII))
            out.flush()

            // 4. Read response status line
            val reader = BufferedReader(InputStreamReader(input, Charsets.US_ASCII))
            val statusLine = reader.readLine()
            val elapsed = System.currentTimeMillis() - start
            if (statusLine != null && (statusLine.contains("204") || statusLine.contains("200") || statusLine.contains("302"))) {
                elapsed
            } else {
                null
            }
        } catch (_: Exception) {
            null
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }
}
