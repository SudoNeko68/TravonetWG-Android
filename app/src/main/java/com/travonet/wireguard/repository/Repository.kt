package com.travonet.wireguard.repository

import android.content.Context
import android.content.SharedPreferences
import com.travonet.wireguard.BuildConfig
import com.travonet.wireguard.model.DefaultStrategies
import com.travonet.wireguard.model.DnsMode
import com.travonet.wireguard.model.EvasionStrategy
import com.travonet.wireguard.model.Subscription
import com.travonet.wireguard.model.TunnelMode
import com.travonet.wireguard.model.WarpRelayMode
import com.travonet.wireguard.model.WgProfile
import org.json.JSONArray
import org.json.JSONObject

class AppRepository(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("travonet_wg_prefs", Context.MODE_PRIVATE)

    companion object {
        // Пресеты живут в отдельном объекте, чтобы их можно было проверить unit-тестами.
        val DEFAULT_STRATEGIES = DefaultStrategies.ALL
        const val DEFAULT_BUILTIN_WARP_RELAY_URL = "https://larp.футанари.рф/register,https://larp.travonet.ru/register"
        const val DEFAULT_BUILTIN_WARP_RELAY_TOKEN = "e11ced0fba59e86a5c0c385d5ab53de072e5c5d7bc7157aea832188a790dd678"
    }

    @Volatile private var cachedProfiles: List<WgProfile>? = null
    @Volatile private var cachedStrategies: List<EvasionStrategy>? = null

    private fun isLegacyDemoProfile(profile: WgProfile): Boolean {
        val nameLower = profile.name.lowercase()
        return nameLower.contains("демо") ||
            nameLower.contains("demo") ||
            nameLower.contains("пример") ||
            profile.rawConfig.contains("OCugIHnrk/r8Zdtd5AGYIchdMag+dqXF08yn1AZ2aUw=")
    }

    // Profiles
    fun getProfiles(): List<WgProfile> {
        cachedProfiles?.let { return it }
        val raw = prefs.getString("wg_profiles", null)
        if (raw.isNullOrBlank()) {
            cachedProfiles = emptyList()
            return emptyList()
        }
        return try {
            val array = JSONArray(raw)
            val list = mutableListOf<WgProfile>()
            var cleanedDemo = false
            for (i in 0 until array.length()) {
                val p = WgProfile.fromJson(array.getJSONObject(i))
                if (isLegacyDemoProfile(p)) {
                    cleanedDemo = true
                    continue
                }
                list.add(p)
            }
            if (cleanedDemo) {
                val newArray = JSONArray()
                list.forEach { newArray.put(it.toJson()) }
                prefs.edit().putString("wg_profiles", newArray.toString()).apply()
                val selectedId = prefs.getString("selected_profile_id", null)
                if (selectedId != null && list.none { it.id == selectedId }) {
                    prefs.edit().putString("selected_profile_id", list.firstOrNull()?.id).apply()
                }
            }
            cachedProfiles = list
            list
        } catch (e: Exception) {
            cachedProfiles = emptyList()
            emptyList()
        }
    }

    fun saveProfiles(profiles: List<WgProfile>) {
        cachedProfiles = profiles
        val array = JSONArray()
        profiles.forEach { array.put(it.toJson()) }
        prefs.edit().putString("wg_profiles", array.toString()).apply()
    }

    fun addOrUpdateProfile(profile: WgProfile) {
        val current = getProfiles().toMutableList()
        val index = current.indexOfFirst { it.id == profile.id }
        if (index >= 0) {
            current[index] = profile
        } else {
            current.add(profile)
        }
        saveProfiles(current)
    }

    fun replaceSubscriptionProfiles(subUrl: String, newProfiles: List<WgProfile>) {
        val current = getProfiles().toMutableList()
        // Only remove profiles belonging to this specific subscription
        current.removeAll { p -> p.subscriptionUrl == subUrl }
        current.addAll(newProfiles)
        saveProfiles(current)
    }

    fun deleteProfile(id: String) {
        val current = getProfiles().toMutableList()
        current.removeAll { it.id == id }
        saveProfiles(current)
        if (getSelectedProfileId() == id) {
            setSelectedProfileId(current.firstOrNull()?.id)
        }
    }

    fun getSelectedProfileId(): String? {
        val id = prefs.getString("selected_profile_id", null)
        if (id != null) return id
        return getProfiles().firstOrNull()?.id
    }

    fun setSelectedProfileId(id: String?) {
        prefs.edit().putString("selected_profile_id", id).apply()
    }

    fun getSelectedProfile(): WgProfile? {
        val id = getSelectedProfileId() ?: return null
        return getProfiles().firstOrNull { it.id == id }
    }

    // Strategies
    fun getStrategies(): List<EvasionStrategy> {
        cachedStrategies?.let { return it }
        val raw = prefs.getString("custom_strategies", null)
        val customList = mutableListOf<EvasionStrategy>()
        if (!raw.isNullOrBlank()) {
            try {
                val array = JSONArray(raw)
                for (i in 0 until array.length()) {
                    customList.add(EvasionStrategy.fromJson(array.getJSONObject(i)))
                }
            } catch (e: Exception) {
                // ignore
            }
        }
        val all = DEFAULT_STRATEGIES + customList
        cachedStrategies = all
        return all
    }

    fun addOrUpdateCustomStrategy(strategy: EvasionStrategy) {
        cachedStrategies = null
        val customOnly = getStrategies().filter { it.isCustom }.toMutableList()
        val index = customOnly.indexOfFirst { it.id == strategy.id }
        if (index >= 0) {
            customOnly[index] = strategy.copy(isCustom = true)
        } else {
            customOnly.add(strategy.copy(isCustom = true))
        }
        val array = JSONArray()
        customOnly.forEach { array.put(it.toJson()) }
        prefs.edit().putString("custom_strategies", array.toString()).apply()
        cachedStrategies = DEFAULT_STRATEGIES + customOnly
    }

    fun deleteCustomStrategy(id: String) {
        cachedStrategies = null
        val customOnly = getStrategies().filter { it.isCustom && it.id != id }
        val array = JSONArray()
        customOnly.forEach { array.put(it.toJson()) }
        prefs.edit().putString("custom_strategies", array.toString()).apply()
        if (getSelectedStrategyId() == id) {
            setSelectedStrategyId("strat_tspu_default")
        }
        cachedStrategies = DEFAULT_STRATEGIES + customOnly
    }

    fun getSelectedStrategyId(): String {
        return prefs.getString("selected_strategy_id", "strat_tspu_default") ?: "strat_tspu_default"
    }

    fun setSelectedStrategyId(id: String) {
        prefs.edit().putString("selected_strategy_id", id).apply()
    }

    fun getSelectedStrategy(): EvasionStrategy {
        val id = getSelectedStrategyId()
        return getStrategies().firstOrNull { it.id == id } ?: DEFAULT_STRATEGIES.first()
    }

    // Tunnel Mode
    fun getTunnelMode(): TunnelMode {
        val modeStr = prefs.getString("tunnel_mode", TunnelMode.VPN.name)
        return try {
            TunnelMode.valueOf(modeStr ?: TunnelMode.VPN.name)
        } catch (e: Exception) {
            TunnelMode.VPN
        }
    }

    fun setTunnelMode(mode: TunnelMode) {
        prefs.edit().putString("tunnel_mode", mode.name).apply()
    }

    // SOCKS5 address
    fun getSocksListenAddr(): String {
        return prefs.getString("socks_listen_addr", "127.0.0.1:1080") ?: "127.0.0.1:1080"
    }

    fun setSocksListenAddr(addr: String) {
        prefs.edit().putString("socks_listen_addr", addr).apply()
    }

    // WARP registration relay. The mode decides whether the build default or
    // the user's custom URL is used, so the user can switch back and forth
    // without losing the custom value.
    fun getWarpRelayMode(): WarpRelayMode {
        val stored = prefs.getString("warp_relay_mode", null)
        if (stored != null) {
            return runCatching { WarpRelayMode.valueOf(stored) }
                .getOrDefault(WarpRelayMode.NONE)
        }

        // Migration from builds that only stored a URL. An explicitly empty
        // URL meant "direct", a non-empty one meant "custom relay".
        if (prefs.contains("warp_relay_url")) {
            return if (prefs.getString("warp_relay_url", "").isNullOrBlank()) {
                WarpRelayMode.NONE
            } else {
                WarpRelayMode.CUSTOM
            }
        }

        return if (getBuiltInWarpRelayUrl().isNotBlank()) {
            WarpRelayMode.AUTO
        } else {
            WarpRelayMode.NONE
        }
    }

    fun setWarpRelayMode(mode: WarpRelayMode) {
        prefs.edit().putString("warp_relay_mode", mode.name).apply()
    }

    fun getWarpRelayUrl(): String {
        return when (getWarpRelayMode()) {
            WarpRelayMode.AUTO -> getBuiltInWarpRelayUrl()
            WarpRelayMode.CUSTOM -> getCustomWarpRelayUrl()
            WarpRelayMode.NONE -> ""
        }
    }

    fun getWarpRelayToken(): String {
        return when (getWarpRelayMode()) {
            WarpRelayMode.AUTO -> getBuiltInWarpRelayToken()
            WarpRelayMode.CUSTOM -> getCustomWarpRelayToken()
            WarpRelayMode.NONE -> ""
        }
    }

    fun getBuiltInWarpRelayUrl(): String =
        BuildConfig.WARP_RELAY_URL.ifBlank { DEFAULT_BUILTIN_WARP_RELAY_URL }

    fun getBuiltInWarpRelayToken(): String =
        BuildConfig.WARP_RELAY_TOKEN.ifBlank { DEFAULT_BUILTIN_WARP_RELAY_TOKEN }

    fun getCustomWarpRelayUrl(): String {
        return prefs.getString("warp_relay_url", "") ?: ""
    }

    fun getCustomWarpRelayToken(): String {
        return prefs.getString("warp_relay_token", "") ?: ""
    }

    /** Saves the selected mode and, for CUSTOM, the URL/token pair. */
    fun saveWarpRelaySettings(mode: WarpRelayMode, url: String, token: String) {
        val editor = prefs.edit().putString("warp_relay_mode", mode.name)
        if (mode == WarpRelayMode.CUSTOM) {
            editor.putString("warp_relay_url", url.trim())
            editor.putString("warp_relay_token", token.trim())
        }
        editor.apply()
    }

    // Kept for the quick relay dialog opened from a failed WARP registration.
    fun setWarpRelayUrl(url: String) {
        val trimmed = url.trim()
        prefs.edit()
            .putString("warp_relay_url", trimmed)
            .putString(
                "warp_relay_mode",
                if (trimmed.isBlank()) WarpRelayMode.NONE.name else WarpRelayMode.CUSTOM.name
            )
            .apply()
    }

    fun setWarpRelayToken(token: String) {
        prefs.edit().putString("warp_relay_token", token.trim()).apply()
    }

    // Reliability & Background Execution Settings
    fun isForegroundServiceEnabled(): Boolean {
        return prefs.getBoolean("foreground_service_enabled", true)
    }

    fun setForegroundServiceEnabled(enabled: Boolean) {
        prefs.edit().putBoolean("foreground_service_enabled", enabled).apply()
    }

    fun isWakeLockEnabled(): Boolean {
        return prefs.getBoolean("wakelock_enabled", true)
    }

    fun setWakeLockEnabled(enabled: Boolean) {
        prefs.edit().putBoolean("wakelock_enabled", enabled).apply()
    }

    fun isAutoReconnectEnabled(): Boolean {
        return prefs.getBoolean("auto_reconnect_enabled", true)
    }

    fun setAutoReconnectEnabled(enabled: Boolean) {
        prefs.edit().putBoolean("auto_reconnect_enabled", enabled).apply()
    }

    fun isShowAddressesEnabled(): Boolean {
        return prefs.getBoolean("show_addresses_enabled", false)
    }

    fun setShowAddressesEnabled(enabled: Boolean) {
        prefs.edit().putBoolean("show_addresses_enabled", enabled).apply()
    }

    // Global DNS Settings
    fun getDnsMode(): DnsMode {
        val raw = prefs.getString("dns_mode", null)
        if (!raw.isNullOrBlank()) {
            runCatching { DnsMode.valueOf(raw) }.getOrNull()?.let { return it }
        }
        // Default to SERVER (DNS through VPN tunnel) for security and reliability.
        return if (isOverrideDns()) DnsMode.CUSTOM else DnsMode.SERVER
    }

    fun setDnsMode(mode: DnsMode) {
        prefs.edit()
            .putString("dns_mode", mode.name)
            .putBoolean("override_dns_enabled", mode != DnsMode.SYSTEM)
            .apply()
    }

    fun getDnsPreset(): String {
        return prefs.getString("dns_preset", "cloudflare") ?: "cloudflare"
    }

    fun setDnsPreset(preset: String) {
        prefs.edit().putString("dns_preset", preset).apply()
    }

    fun getCustomDns(): String {
        return prefs.getString("custom_dns", "1.1.1.1, 8.8.8.8") ?: "1.1.1.1, 8.8.8.8"
    }

    fun setCustomDns(customDns: String) {
        prefs.edit().putString("custom_dns", customDns.trim()).apply()
    }

    fun getCustomDnsType(): String {
        return prefs.getString("custom_dns_type", "DOH") ?: "DOH"
    }

    fun setCustomDnsType(type: String) {
        prefs.edit().putString("custom_dns_type", type.uppercase()).apply()
    }

    fun getCustomDnsUdp(): String {
        return prefs.getString("custom_dns_udp", "1.1.1.1, 1.0.0.1") ?: "1.1.1.1, 1.0.0.1"
    }

    fun setCustomDnsUdp(value: String) {
        prefs.edit().putString("custom_dns_udp", value.trim()).apply()
    }

    fun getCustomDnsDot(): String {
        return prefs.getString("custom_dns_dot", "tls://1.1.1.1:853") ?: "tls://1.1.1.1:853"
    }

    fun setCustomDnsDot(value: String) {
        prefs.edit().putString("custom_dns_dot", value.trim()).apply()
    }

    fun getCustomDnsDoh(): String {
        return prefs.getString("custom_dns_doh", "https://1.1.1.1/dns-query") ?: "https://1.1.1.1/dns-query"
    }

    fun setCustomDnsDoh(value: String) {
        prefs.edit().putString("custom_dns_doh", value.trim()).apply()
    }

    fun getCustomHosts(): String {
        return prefs.getString("custom_hosts", "") ?: ""
    }

    fun setCustomHosts(value: String) {
        prefs.edit().putString("custom_hosts", value).apply()
    }

    fun isOverrideDns(): Boolean {
        return prefs.getBoolean("override_dns_enabled", false)
    }

    fun setOverrideDns(enabled: Boolean) {
        prefs.edit().putBoolean("override_dns_enabled", enabled).apply()
    }

    fun getEffectiveDnsServers(): List<String> {
        when (getDnsMode()) {
            DnsMode.SYSTEM -> return emptyList()
            DnsMode.SERVER -> return listOf("1.1.1.1", "1.0.0.1")
            DnsMode.CUSTOM -> Unit
        }
        val udpList = getCustomDnsUdp().split(",", " ", ";")
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("http", ignoreCase = true) && !it.startsWith("tls", ignoreCase = true) }
        val fallbackUdp = if (udpList.isNotEmpty()) udpList else listOf("1.1.1.1", "1.0.0.1")

        return when (getDnsPreset().lowercase()) {
            "cloudflare" -> listOf("1.1.1.1", "1.0.0.1")
            "google" -> listOf("8.8.8.8", "8.8.4.4")
            "adguard" -> listOf("94.140.14.14", "94.140.15.15")
            "quad9" -> listOf("9.9.9.9", "149.112.112.112")
            "custom" -> {
                when (getCustomDnsType().uppercase()) {
                    "UDP" -> fallbackUdp
                    "DOT" -> {
                        val dot = getCustomDnsDot().removePrefix("tls://").substringBefore(':').substringBefore('/')
                        if (dot.matches(Regex("\\d+\\.\\d+\\.\\d+\\.\\d+"))) listOf(dot) else fallbackUdp
                    }
                    else -> fallbackUdp
                }
            }
            "system" -> emptyList()
            else -> listOf("1.1.1.1", "1.0.0.1")
        }
    }

    fun getEffectiveDnsDohUrl(): String {
        when (getDnsMode()) {
            DnsMode.SYSTEM -> return "local"
            DnsMode.SERVER -> return "https://1.1.1.1/dns-query"
            DnsMode.CUSTOM -> Unit
        }
        if (getDnsPreset().lowercase() == "custom") {
            return when (getCustomDnsType().uppercase()) {
                "UDP" -> {
                    val rawUdp = getCustomDnsUdp().trim()
                    val firstIp = rawUdp.split(",", " ", ";").firstOrNull { it.isNotBlank() } ?: "1.1.1.1"
                    "udp://$firstIp"
                }
                "DOT" -> {
                    val rawDot = getCustomDnsDot().trim()
                    if (rawDot.startsWith("tls://", ignoreCase = true)) rawDot else "tls://$rawDot"
                }
                else -> {
                    val rawDoh = getCustomDnsDoh().trim()
                    if (rawDoh.startsWith("https://", ignoreCase = true)) rawDoh else "https://$rawDoh"
                }
            }
        }
        return when (getDnsPreset().lowercase()) {
            "cloudflare" -> "https://1.1.1.1/dns-query"
            "google" -> "https://dns.google/dns-query"
            "adguard" -> "https://dns.adguard-dns.com/dns-query"
            "quad9" -> "https://dns.quad9.net/dns-query"
            "system" -> "local"
            else -> "https://1.1.1.1/dns-query"
        }
    }

    // Subscription Settings (Multi-subscription support & legacy compatibility)
    fun getSubscriptions(): List<Subscription> {
        val raw = prefs.getString("subscriptions_list", null)
        val list = mutableListOf<Subscription>()
        if (!raw.isNullOrBlank()) {
            try {
                val arr = JSONArray(raw)
                for (i in 0 until arr.length()) {
                    list.add(Subscription.fromJson(arr.getJSONObject(i)))
                }
            } catch (_: Exception) {}
        }

        // Migrate legacy single subscription if not yet in the list
        val legacyUrl = prefs.getString("subscription_url", null)?.takeIf { it.isNotBlank() }
        if (legacyUrl != null && list.none { it.url == legacyUrl }) {
            val title = prefs.getString("subscription_title", "Подписка") ?: "Подписка"
            val lastUpdate = prefs.getLong("subscription_last_update", 0L)
            val sub = Subscription(url = legacyUrl, title = title, lastUpdate = lastUpdate)
            list.add(0, sub)
            saveSubscriptions(list)
        }

        // Auto-discover any subscriptions referenced by loaded profiles
        val profileSubUrls = getProfiles().mapNotNull { it.subscriptionUrl }.distinct()
        var addedAny = false
        for (u in profileSubUrls) {
            if (list.none { it.url == u }) {
                list.add(Subscription(url = u, title = "Подписка"))
                addedAny = true
            }
        }
        if (addedAny) {
            saveSubscriptions(list)
        }

        return list
    }

    fun saveSubscriptions(subs: List<Subscription>) {
        val arr = JSONArray()
        subs.forEach { arr.put(it.toJson()) }
        prefs.edit().putString("subscriptions_list", arr.toString()).apply()
    }

    fun addOrUpdateSubscription(sub: Subscription) {
        val current = getSubscriptions().toMutableList()
        val index = current.indexOfFirst { it.url == sub.url }
        if (index >= 0) {
            current[index] = sub
        } else {
            current.add(sub)
        }
        saveSubscriptions(current)
        setSubscriptionUrl(sub.url)
        setSubscriptionTitle(sub.title)
        setLastSubscriptionUpdate(sub.lastUpdate)
    }

    fun deleteSubscription(url: String) {
        // 1. Remove subscription from list
        val current = getSubscriptions().toMutableList()
        current.removeAll { it.url == url }
        saveSubscriptions(current)

        if (getSubscriptionUrl() == url) {
            val next = current.firstOrNull()
            setSubscriptionUrl(next?.url)
            setSubscriptionTitle(next?.title)
            setLastSubscriptionUpdate(next?.lastUpdate ?: 0L)
        }

        // 2. Remove all profiles belonging to this subscription
        val currentProfiles = getProfiles().toMutableList()
        val toRemove = currentProfiles.filter { it.subscriptionUrl == url }
        currentProfiles.removeAll { it.subscriptionUrl == url }
        saveProfiles(currentProfiles)

        // 3. Update selected profile if the deleted one was selected
        val selectedId = getSelectedProfileId()
        if (toRemove.any { it.id == selectedId }) {
            setSelectedProfileId(currentProfiles.firstOrNull()?.id)
        }
    }

    fun getSubscriptionUrl(): String? {
        return prefs.getString("subscription_url", null)?.takeIf { it.isNotBlank() }
    }

    fun setSubscriptionUrl(url: String?) {
        prefs.edit().putString("subscription_url", url?.trim()).apply()
    }

    fun getSubscriptionTitle(): String? {
        return prefs.getString("subscription_title", null)?.takeIf { it.isNotBlank() }
    }

    fun setSubscriptionTitle(title: String?) {
        prefs.edit().putString("subscription_title", title?.trim()).apply()
    }

    fun getLastSubscriptionUpdate(): Long {
        return prefs.getLong("subscription_last_update", 0L)
    }

    fun setLastSubscriptionUpdate(timestamp: Long) {
        prefs.edit().putLong("subscription_last_update", timestamp).apply()
    }

    // Protocol Delegations
    fun getProtocolDelegations(): Map<String, String> {
        val raw = prefs.getString("protocol_delegations", null) ?: return emptyMap()
        return try {
            val json = JSONObject(raw)
            val map = mutableMapOf<String, String>()
            val keys = json.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                map[k] = json.getString(k)
            }
            map
        } catch (_: Exception) {
            emptyMap()
        }
    }

    fun setProtocolDelegation(protocolId: String, coreId: String) {
        val current = getProtocolDelegations().toMutableMap()
        current[protocolId] = coreId
        val json = JSONObject()
        current.forEach { (k, v) -> json.put(k, v) }
        prefs.edit().putString("protocol_delegations", json.toString()).apply()
    }

    fun resetProtocolDelegations() {
        prefs.edit().remove("protocol_delegations").apply()
    }

    fun getSelectedCoreVersion(coreId: String): String? {
        return prefs.getString("core_version_$coreId", null)
    }

    fun setSelectedCoreVersion(coreId: String, version: String) {
        prefs.edit().putString("core_version_$coreId", version).apply()
    }
}
