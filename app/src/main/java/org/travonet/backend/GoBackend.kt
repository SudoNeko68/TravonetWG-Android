package org.travonet.backend

object GoBackend {
    @Volatile
    private var isLoaded = false

    @JvmStatic
    fun loadCustomCore(filePath: String?): Boolean {
        if (!filePath.isNullOrBlank()) {
            val f = java.io.File(filePath)
            if (f.exists() && f.length() > 1024 * 1024) {
                try {
                    System.load(f.absolutePath)
                    isLoaded = true
                    android.util.Log.i("GoBackend", "Successfully loaded custom rolling core from $filePath")
                    return true
                } catch (e: Throwable) {
                    android.util.Log.w("GoBackend", "Failed to load custom core $filePath, falling back to built-in", e)
                }
            }
        }
        return ensureLoaded()
    }

    @JvmStatic
    fun ensureLoaded(): Boolean {
        if (isLoaded) return true
        try {
            System.loadLibrary("travonet-wg")
            isLoaded = true
            return true
        } catch (e: UnsatisfiedLinkError) {
            try {
                System.loadLibrary("wg-go")
                isLoaded = true
                return true
            } catch (e2: UnsatisfiedLinkError) {
                android.util.Log.e("GoBackend", "Failed to load builtin library", e2)
                return false
            }
        }
    }

    init {
        ensureLoaded()
    }

    // --- Защита сокетов через VpnService.protect(fd) ---
    // Регистрирует VpnService до создания туннеля; null освобождает ссылку.
    @JvmStatic
    external fun wgSetVpnService(vpnService: Any?)

    // Рекомендуемый запуск: protect(fd) применяется к каждому UDP-сокету ещё до
    // bind() и до отправки первого handshake.
    @JvmStatic
    external fun wgTurnOnProtected(ifname: String, tunFd: Int, settings: String, vpnService: Any?): Int

    // Снимает барьер защиты сокета для легаси-сценария (protect после wgTurnOn).
    @JvmStatic
    external fun wgNotifySocketProtected(handle: Int)

    // Режим VpnService TUN
    @JvmStatic
    external fun wgTurnOn(ifname: String, tunFd: Int, settings: String): Int

    @JvmStatic
    external fun wgTurnOff(handle: Int)

    @JvmStatic
    external fun wgGetSocketV4(handle: Int): Int

    @JvmStatic
    external fun wgGetSocketV6(handle: Int): Int

    @JvmStatic
    external fun wgGetConfig(handle: Int): String?

    @JvmStatic
    external fun wgVersion(): String?

    // Режим Userspace SOCKS5
    @JvmStatic
    external fun wgStartSocks5(listenAddr: String, settings: String): Int

    @JvmStatic
    external fun wgStopSocks5(handle: Int)

    @JvmStatic
    external fun wgGetSocks5SocketV4(handle: Int): Int

    @JvmStatic
    external fun wgGetSocks5SocketV6(handle: Int): Int

    // --- Генерация WARP (Cloudflare) ---
    // Возвращает JSON {"private_key": "...", "public_key": "..."}.
    @JvmStatic
    external fun wgGenerateKeypair(): String?

    // Регистрирует анонимное устройство WARP и возвращает сырой JSON API.
    // relayUrl/relayToken могут быть пустыми — тогда только прямые попытки.
    @JvmStatic
    external fun wgRegisterWarp(
        publicKey: String,
        locale: String,
        model: String,
        relayUrl: String,
        relayToken: String
    ): String?

    // Декодирует ссылку vpn:// от Amnezia, возвращает JSON {"name": "...", "config": "[Interface]..."}
    @JvmStatic
    external fun wgParseVPNURL(vpnUrl: String): String?
}
