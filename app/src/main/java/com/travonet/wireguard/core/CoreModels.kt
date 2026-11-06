package com.travonet.wireguard.core

enum class CoreType(
    val id: String,
    val title: String,
    val binaryName: String,
    val description: String
) {
    TRAVONET_WG(
        id = "travonet_wg",
        title = "TravonetWG",
        binaryName = "libtravonet-wg.so",
        description = "Нативное ядро WireGuard и AmneziaWG со встроенной десинхронизацией DPI (L3/L4)"
    ),
    XRAY(
        id = "xray",
        title = "Xray-Core",
        binaryName = "libxray.so",
        description = "Универсальное ядро для VLESS (Reality / XTLS-Vision), VMess, Trojan и Shadowsocks"
    ),
    SINGBOX(
        id = "singbox",
        title = "Sing-Box",
        binaryName = "libsingbox.so",
        description = "Высокоскоростное ядро для протоколов TUIC, Hysteria 2 и ShadowTLS"
    ),
    FREETURN(
        id = "freeturn",
        title = "FreeTURN",
        binaryName = "libfreeturn.so",
        description = "Клиентское ядро FreeTURN Proxy для туннелирования трафика через TURN/VK-звонки"
    )
}

enum class CoreStatus(val label: String) {
    BUILTIN("Встроено"),
    INSTALLED("Установлено"),
    UPDATE_AVAILABLE("Доступно обновление"),
    DOWNLOADING("Загрузка..."),
    NOT_INSTALLED("Доступно к установке")
}

data class CoreInfo(
    val type: CoreType,
    val version: String,
    val availableVersions: List<String> = emptyList(),
    val selectedVersion: String = version,
    val status: CoreStatus,
    val sizeBytes: Long = 0,
    val supportedProtocols: List<String>,
    val filePath: String? = null,
    val downloadProgress: Float = 0f
) {
    fun formattedSize(): String {
        if (sizeBytes <= 0) return "Встроено"
        val mb = sizeBytes.toDouble() / (1024 * 1024)
        return String.format(java.util.Locale.US, "%.1f МБ", mb)
    }
}

enum class SupportedProtocol(
    val id: String,
    val displayName: String,
    val defaultCore: CoreType,
    val compatibleCores: List<CoreType>,
    val description: String,
    val exampleUri: String
) {
    WIREGUARD(
        id = "wireguard",
        displayName = "WireGuard",
        defaultCore = CoreType.TRAVONET_WG,
        compatibleCores = listOf(CoreType.TRAVONET_WG),
        description = "Классический протокол WireGuard с активной L3/L4 десинхронизацией DPI",
        exampleUri = "wireguard://... или wg://..."
    ),
    AMNEZIA_WG(
        id = "amneziawg",
        displayName = "AmneziaWG",
        defaultCore = CoreType.TRAVONET_WG,
        compatibleCores = listOf(CoreType.TRAVONET_WG),
        description = "AmneziaWG с прелюдией I1, заголовками H1–H4 и мусорными пакетами Jc",
        exampleUri = "vpn://... или .conf с параметрами Jc/H1/S1"
    ),
    WARP(
        id = "warp",
        displayName = "Cloudflare WARP",
        defaultCore = CoreType.TRAVONET_WG,
        compatibleCores = listOf(CoreType.TRAVONET_WG),
        description = "Профиль WARP с защитой от блокировок эндпоинтов и встроенными релеями",
        exampleUri = "warp://"
    ),
    VLESS(
        id = "vless",
        displayName = "VLESS (Reality)",
        defaultCore = CoreType.XRAY,
        compatibleCores = listOf(CoreType.XRAY, CoreType.SINGBOX),
        description = "XTLS-Vision и Reality маскировка под TLS-трафик",
        exampleUri = "vless://uuid@host:port?security=reality&flow=xtls-rprx-vision..."
    ),
    VMESS(
        id = "vmess",
        displayName = "VMess",
        defaultCore = CoreType.XRAY,
        compatibleCores = listOf(CoreType.XRAY, CoreType.SINGBOX),
        description = "Протокол VMess с поддержкой AEAD, gRPC, WebSocket и шифрования",
        exampleUri = "vmess://base64-json"
    ),
    TROJAN(
        id = "trojan",
        displayName = "Trojan",
        defaultCore = CoreType.XRAY,
        compatibleCores = listOf(CoreType.XRAY, CoreType.SINGBOX),
        description = "Протокол Trojan через TLS с маскировкой под веб-трафик",
        exampleUri = "trojan://password@host:port?security=tls..."
    ),
    SHADOWSOCKS(
        id = "shadowsocks",
        displayName = "Shadowsocks",
        defaultCore = CoreType.XRAY,
        compatibleCores = listOf(CoreType.XRAY, CoreType.SINGBOX),
        description = "Протокол Shadowsocks (SIP002, AEAD шифры 2022 / ChaCha20 / AES-GCM)",
        exampleUri = "ss://base64@host:port"
    ),
    TUIC(
        id = "tuic",
        displayName = "TUIC",
        defaultCore = CoreType.SINGBOX,
        compatibleCores = listOf(CoreType.SINGBOX),
        description = "Высокоскоростной UDP-прокси протокол TUIC v5 на базе QUIC",
        exampleUri = "tuic://uuid:password@host:port?congestion_control=bbr..."
    ),
    HYSTERIA2(
        id = "hysteria2",
        displayName = "Hysteria 2",
        defaultCore = CoreType.SINGBOX,
        compatibleCores = listOf(CoreType.SINGBOX, CoreType.XRAY),
        description = "Быстрый протокол Hysteria 2 (UDP/QUIC) со встроенной BBR-оптимизацией",
        exampleUri = "hysteria2://password@host:port или hy2://..."
    ),
    SHADOWTLS(
        id = "shadowtls",
        displayName = "ShadowTLS",
        defaultCore = CoreType.SINGBOX,
        compatibleCores = listOf(CoreType.SINGBOX),
        description = "Маскировка TLS-рукопожатия под популярные доверенные домены",
        exampleUri = "shadowtls://..."
    ),
    FREETURN(
        id = "freeturn",
        displayName = "FreeTURN",
        defaultCore = CoreType.FREETURN,
        compatibleCores = listOf(CoreType.FREETURN),
        description = "Прокси-туннелирование трафика через TURN-серверы и WebRTC (VK)",
        exampleUri = "freeturn://base64-json"
    )
}

data class ProtocolRoutingRule(
    val protocol: String,
    val targetCore: CoreType,
    val description: String,
    val exampleUri: String,
    val isPreferred: Boolean = true
)

data class RoutingResult(
    val targetCore: CoreType,
    val detectedProtocol: String,
    val rule: ProtocolRoutingRule,
    val explanation: String
)

typealias MicroParserResult = RoutingResult
