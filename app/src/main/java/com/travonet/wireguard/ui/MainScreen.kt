package com.travonet.wireguard.ui

import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.travonet.wireguard.model.EvasionStrategy
import com.travonet.wireguard.model.Subscription
import com.travonet.wireguard.model.TunnelMode
import com.travonet.wireguard.model.WarpRelayMode
import com.travonet.wireguard.model.WgProfile
import com.travonet.wireguard.parser.WgConfigParser
import com.travonet.wireguard.repository.AppRepository
import com.travonet.wireguard.service.PingHelper
import com.travonet.wireguard.service.PingResult
import com.travonet.wireguard.service.TunnelManager
import com.travonet.wireguard.subscription.SubscriptionFetcher
import com.travonet.wireguard.ui.components.BottomControlBar
import com.travonet.wireguard.ui.dialogs.AddEditProfileDialog
import com.travonet.wireguard.ui.dialogs.AddFreeTurnDialog
import com.travonet.wireguard.ui.dialogs.AppSettingsDialog
import com.travonet.wireguard.ui.dialogs.CaptchaDialog
import com.travonet.wireguard.ui.dialogs.SubscriptionDialog
import com.travonet.wireguard.ui.dialogs.WarpProgressDialog
import com.travonet.wireguard.ui.dialogs.WarpRelayDialog
import com.travonet.wireguard.ui.dialogs.WarpUiState
import androidx.compose.material.icons.filled.PhoneInTalk
import com.travonet.wireguard.core.CoreManager
import com.travonet.wireguard.ui.screens.ConfigsScreen
import com.travonet.wireguard.ui.screens.CoresScreen
import com.travonet.wireguard.ui.screens.StrategiesScreen
import com.travonet.wireguard.warp.WarpGenerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.travonet.backend.GoBackend
import java.io.BufferedReader
import java.io.InputStreamReader

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    onRequestStartTunnel: (WgProfile, EvasionStrategy, TunnelMode) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val repository = remember { AppRepository(context) }
    val coreManager = remember { CoreManager(context) }

    val pagerState = rememberPagerState(pageCount = { 3 })
    var profiles by remember { mutableStateOf(repository.getProfiles()) }
    var selectedProfileId by remember { mutableStateOf(repository.getSelectedProfileId()) }

    var strategies by remember { mutableStateOf(repository.getStrategies()) }
    var selectedStrategyId by remember { mutableStateOf(repository.getSelectedStrategyId()) }

    var tunnelMode by remember { mutableStateOf(repository.getTunnelMode()) }
    var socksAddr by remember { mutableStateOf(repository.getSocksListenAddr()) }

    var showSettingsDialog by remember { mutableStateOf(false) }
    var showInfoDialog by remember { mutableStateOf(false) }

    var showAddresses by remember { mutableStateOf(repository.isShowAddressesEnabled()) }
    var pingResults by remember { mutableStateOf<Map<String, PingResult>>(emptyMap()) }
    var isTestingAll by remember { mutableStateOf(false) }

    var isPingingBottom by remember { mutableStateOf(false) }
    var bottomPingLatency by remember { mutableStateOf<Long?>(null) }

    var isAddingProfile by remember { mutableStateOf(false) }

    var warpUiState by remember { mutableStateOf<WarpUiState?>(null) }
    var showWarpRelayDialog by remember { mutableStateOf(false) }
    var warpRelayMode by remember { mutableStateOf(repository.getWarpRelayMode()) }
    var warpRelayUrl by remember { mutableStateOf(repository.getWarpRelayUrl()) }
    var warpRelayToken by remember { mutableStateOf(repository.getWarpRelayToken()) }

    var showSubscriptionDialog by remember { mutableStateOf(false) }
    var showAddFreeTurnDialog by remember { mutableStateOf(false) }
    val captchaUrl by TunnelManager.captchaUrl.collectAsState()
    var isFetchingSubscription by remember { mutableStateOf(false) }
    var updatingSubscriptionUrls by remember { mutableStateOf<Set<String>>(emptySet()) }
    var subscriptionErrorMessage by remember { mutableStateOf<String?>(null) }
    var subscriptionUrl by remember { mutableStateOf(repository.getSubscriptionUrl() ?: "") }
    var subscriptions by remember { mutableStateOf(repository.getSubscriptions()) }
    var protocolDelegations by remember { mutableStateOf(repository.getProtocolDelegations()) }

    val scope = rememberCoroutineScope()

    val activeFallbackStrategy = remember(strategies, selectedStrategyId) {
        strategies.firstOrNull { it.id == selectedStrategyId } ?: strategies.first()
    }

    // File picker launcher
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            try {
                val inputStream = context.contentResolver.openInputStream(uri)
                val reader = BufferedReader(InputStreamReader(inputStream))
                val content = reader.readText()
                reader.close()

                val fileName = uri.lastPathSegment?.substringAfterLast('/')?.removeSuffix(".conf")
                    ?: "Импортированный профиль"
                val profile = WgConfigParser.parseProfile(fileName, content)
                repository.addOrUpdateProfile(profile)
                profiles = repository.getProfiles()
                selectedProfileId = profile.id
                repository.setSelectedProfileId(profile.id)
                scope.launch { pagerState.animateScrollToPage(0) }
                Toast.makeText(context, "Конфигурация импортирована!", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(context, "Ошибка чтения файла: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
            }
        }
    }

    fun fetchSubscription(urlStr: String) {
        if (updatingSubscriptionUrls.contains(urlStr)) return
        updatingSubscriptionUrls = updatingSubscriptionUrls + urlStr
        isFetchingSubscription = true
        subscriptionErrorMessage = null
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    SubscriptionFetcher.fetchSubscription(urlStr)
                }
            }
            result.onSuccess { subResult ->
                val parsed = Subscription.parseUserInfo(subResult.userInfo)
                val newSub = Subscription(
                    url = urlStr,
                    title = subResult.title,
                    lastUpdate = System.currentTimeMillis(),
                    updateIntervalHours = subResult.updateIntervalHours,
                    uploadBytes = parsed.upload,
                    downloadBytes = parsed.download,
                    totalBytes = parsed.total,
                    expireTimeSec = parsed.expire
                )
                repository.addOrUpdateSubscription(newSub)
                repository.replaceSubscriptionProfiles(urlStr, subResult.profiles)
                profiles = repository.getProfiles()
                subscriptions = repository.getSubscriptions()
                subscriptionUrl = repository.getSubscriptionUrl() ?: ""
                if (selectedProfileId == null || profiles.none { it.id == selectedProfileId }) {
                    selectedProfileId = subResult.profiles.firstOrNull()?.id
                    repository.setSelectedProfileId(selectedProfileId)
                }
                scope.launch { pagerState.animateScrollToPage(0) }
                updatingSubscriptionUrls = updatingSubscriptionUrls - urlStr
                isFetchingSubscription = updatingSubscriptionUrls.isNotEmpty()
                showSubscriptionDialog = false
                Toast.makeText(
                    context,
                    "Подписка «${subResult.title}» обновлена: ${subResult.profiles.size} конф.",
                    Toast.LENGTH_LONG
                ).show()
            }.onFailure { err ->
                updatingSubscriptionUrls = updatingSubscriptionUrls - urlStr
                isFetchingSubscription = updatingSubscriptionUrls.isNotEmpty()
                subscriptionErrorMessage = err.localizedMessage ?: "Ошибка загрузки подписки"
                Toast.makeText(context, "Ошибка подписки: ${err.localizedMessage}", Toast.LENGTH_LONG).show()
            }
        }
    }

    fun deleteSubscription(url: String) {
        repository.deleteSubscription(url)
        subscriptions = repository.getSubscriptions()
        profiles = repository.getProfiles()
        selectedProfileId = repository.getSelectedProfileId()
        subscriptionUrl = repository.getSubscriptionUrl() ?: ""
        Toast.makeText(context, "Подписка удалена", Toast.LENGTH_SHORT).show()
    }

    fun pasteFromClipboard() {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val rawText = clip.getItemAt(0).text?.toString() ?: ""
            val text = rawText.trim()
            if (text.isBlank()) {
                Toast.makeText(context, "Буфер обмена пуст", Toast.LENGTH_SHORT).show()
                return
            }

            val httpRegex = Regex("""https?://[^\s"'<>]+""", RegexOption.IGNORE_CASE)
            val vpnRegex = Regex("""vpn://[^\s"'<>]+""", RegexOption.IGNORE_CASE)
            val wgRegex = Regex("""(wireguard|wg)://[^\s"'<>]+""", RegexOption.IGNORE_CASE)
            val interfaceRegex = Regex("""\[Interface\]""", RegexOption.IGNORE_CASE)

            val httpMatch = httpRegex.find(text)
            val vpnMatch = vpnRegex.find(text)
            val wgMatch = wgRegex.find(text)
            val hasInterface = interfaceRegex.containsMatchIn(text)

            when {
                // Subscription URL (HTTP/HTTPS without proxy scheme or [Interface])
                httpMatch != null && !hasInterface && !com.travonet.wireguard.parser.ProxyLinkParser.isProxyLink(text) -> {
                    val url = httpMatch.value.trim().trimEnd('.', ',', ';')
                    subscriptionUrl = url
                    Toast.makeText(context, "Загрузка подписки...", Toast.LENGTH_SHORT).show()
                    fetchSubscription(url)
                }
                // Any supported proxy link (VLESS, VMess, Trojan, Shadowsocks, TUIC, Hysteria 2, WireGuard, AmneziaWG)
                com.travonet.wireguard.parser.ProxyLinkParser.isProxyLink(text) -> {
                    val profile = com.travonet.wireguard.parser.ProxyLinkParser.parse(text, "Профиль из буфера")
                    if (profile != null) {
                        repository.addOrUpdateProfile(profile)
                        profiles = repository.getProfiles()
                        selectedProfileId = profile.id
                        repository.setSelectedProfileId(profile.id)
                        scope.launch { pagerState.animateScrollToPage(0) }
                        Toast.makeText(context, "Импортировано: ${profile.name}", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(context, "Не удалось разобрать прокси-ссылку", Toast.LENGTH_SHORT).show()
                    }
                }
                // Standard WireGuard / AmneziaWG .conf configuration
                hasInterface -> {
                    val profile = WgConfigParser.parseProfile("Профиль из буфера", text)
                    repository.addOrUpdateProfile(profile)
                    profiles = repository.getProfiles()
                    selectedProfileId = profile.id
                    repository.setSelectedProfileId(profile.id)
                    scope.launch { pagerState.animateScrollToPage(0) }
                    Toast.makeText(context, "Импортировано: ${profile.name}", Toast.LENGTH_SHORT).show()
                }
                else -> {
                    // Try parsing as multi-line subscription/profile list
                    val parsedList = com.travonet.wireguard.subscription.SubscriptionFetcher.parseSubscriptionBody(text, "Буфер")
                    if (parsedList.isNotEmpty()) {
                        parsedList.forEach { repository.addOrUpdateProfile(it) }
                        profiles = repository.getProfiles()
                        selectedProfileId = parsedList.first().id
                        repository.setSelectedProfileId(selectedProfileId)
                        scope.launch { pagerState.animateScrollToPage(0) }
                        Toast.makeText(context, "Импортировано профилей: ${parsedList.size}", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(
                            context,
                            "Буфер не содержит конфигурацию, прокси-ссылку или URL подписки",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }
            }
        } else {
            Toast.makeText(context, "Буфер обмена пуст", Toast.LENGTH_SHORT).show()
        }
    }

    fun generateWarp() {
        if (warpUiState is WarpUiState.Running) return

        val name = WarpGenerator.nextName(profiles)
        val relayUrl = warpRelayUrl
        val relayToken = warpRelayToken
        warpUiState = WarpUiState.Running

        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { WarpGenerator.generate(name, relayUrl, relayToken) }
            }
            result.onSuccess { profile ->
                repository.addOrUpdateProfile(profile)
                profiles = repository.getProfiles()
                selectedProfileId = profile.id
                repository.setSelectedProfileId(profile.id)
                scope.launch { pagerState.animateScrollToPage(0) }
                warpUiState = WarpUiState.Success(profile.name, profile.endpoint)
            }.onFailure { error ->
                warpUiState = WarpUiState.Failure(
                    error.message?.takeIf { it.isNotBlank() }
                        ?: "Ошибка ${error.javaClass.simpleName}"
                )
            }
        }
    }

    fun pingProfilesSubset(targetProfiles: List<WgProfile>) {
        if (isTestingAll || targetProfiles.isEmpty()) return
        isTestingAll = true
        scope.launch {
            for (profile in targetProfiles) {
                pingResults = pingResults + (profile.id to PingResult(isTesting = true))
                val udpPing = PingHelper.pingUdpHost(profile.endpoint)
                if (udpPing != null) {
                    val strategy = if (profile.hasEmbeddedStrategy) {
                        val embedded = profile.embeddedStrategy ?: activeFallbackStrategy.name
                        strategies.firstOrNull { it.name.equals(embedded, ignoreCase = true) } ?: activeFallbackStrategy
                    } else {
                        activeFallbackStrategy
                    }
                    val httpPing = PingHelper.pingHttp204(profile, strategy)
                    pingResults = pingResults + (profile.id to PingResult(
                        udpPingMs = udpPing,
                        udpError = false,
                        httpPingMs = httpPing,
                        httpError = httpPing == null,
                        isTesting = false
                    ))
                } else {
                    pingResults = pingResults + (profile.id to PingResult(
                        udpPingMs = null,
                        udpError = true,
                        httpPingMs = null,
                        httpError = true,
                        isTesting = false
                    ))
                }
            }
            isTestingAll = false
        }
    }

    fun pingAllProfiles() {
        pingProfilesSubset(profiles)
    }

    fun pingSelectedProfile() {
        val activeProf = profiles.firstOrNull { it.id == selectedProfileId } ?: profiles.firstOrNull()
        if (activeProf == null) {
            Toast.makeText(context, "Выберите конфигурацию для пинга!", Toast.LENGTH_SHORT).show()
            return
        }
        if (isPingingBottom) return
        isPingingBottom = true
        scope.launch {
            val strategy = if (activeProf.hasEmbeddedStrategy) {
                val embedded = activeProf.embeddedStrategy ?: activeFallbackStrategy.name
                strategies.firstOrNull { it.name.equals(embedded, ignoreCase = true) } ?: activeFallbackStrategy
            } else {
                activeFallbackStrategy
            }
            val latency = PingHelper.pingHttp204(activeProf, strategy)
            bottomPingLatency = latency
            isPingingBottom = false
            if (latency != null) {
                Toast.makeText(context, "Ping: $latency мс (Google 204)", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(context, "Ошибка пинга (Google 204 недоступен)", Toast.LENGTH_SHORT).show()
            }
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                            Text(
                                text = "TravonetVPN",
                                fontWeight = FontWeight.Black,
                                fontSize = 20.sp
                            )
                            Spacer(Modifier.width(8.dp))
                            Badge(
                                containerColor = MaterialTheme.colorScheme.primaryContainer,
                                contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                            ) {
                                Text("DPI Bypass", fontSize = 10.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 4.dp))
                            }
                        }
                    },
                    actions = {
                        IconButton(onClick = { showSettingsDialog = true }) {
                            Icon(Icons.Default.Settings, contentDescription = "Настройки")
                        }

                        AddConfigMenuButton(
                            onPasteFromClipboard = { pasteFromClipboard() },
                            onImportFromFile = { filePickerLauncher.launch("*/*") },
                            onGenerateWarp = { generateWarp() },
                            onCreateManual = { isAddingProfile = true },
                            onOpenSubscription = { showSubscriptionDialog = true },
                            onOpenFreeTurn = { showAddFreeTurnDialog = true },
                            onUpdateSubscription = if (subscriptionUrl.isNotBlank()) {
                                { fetchSubscription(subscriptionUrl) }
                            } else null
                        )

                        IconButton(onClick = { showInfoDialog = true }) {
                            Icon(Icons.Default.Info, contentDescription = "О программе")
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                )

                // The two top tab switchers with swipe pager support
                PrimaryTabRow(
                    selectedTabIndex = pagerState.currentPage,
                    containerColor = MaterialTheme.colorScheme.surface
                ) {
                    Tab(
                        selected = pagerState.currentPage == 0,
                        onClick = {
                            scope.launch { pagerState.animateScrollToPage(0) }
                        },
                        text = {
                            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                Icon(Icons.Default.Dns, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Конфигурации (${profiles.size})", fontWeight = if (pagerState.currentPage == 0) FontWeight.Bold else FontWeight.Normal)
                            }
                        }
                    )

                    Tab(
                        selected = pagerState.currentPage == 1,
                        onClick = {
                            scope.launch { pagerState.animateScrollToPage(1) }
                        },
                        text = {
                            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                Icon(Icons.Default.Bolt, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Стратегии", fontWeight = if (pagerState.currentPage == 1) FontWeight.Bold else FontWeight.Normal)
                            }
                        }
                    )

                    Tab(
                        selected = pagerState.currentPage == 2,
                        onClick = {
                            scope.launch { pagerState.animateScrollToPage(2) }
                        },
                        text = {
                            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                Icon(Icons.Default.Memory, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Ядра", fontWeight = if (pagerState.currentPage == 2) FontWeight.Bold else FontWeight.Normal)
                            }
                        }
                    )
                }
            }
        },
        bottomBar = {
            BottomControlBar(
                selectedMode = tunnelMode,
                socksAddr = socksAddr,
                onModeChange = { newMode ->
                    tunnelMode = newMode
                    repository.setTunnelMode(newMode)
                },
                onStartClick = {
                    val activeProf = profiles.firstOrNull { it.id == selectedProfileId }
                        ?: profiles.firstOrNull()
                    if (activeProf == null) {
                        Toast.makeText(context, "Выберите конфигурацию!", Toast.LENGTH_SHORT).show()
                        return@BottomControlBar
                    }
                    val routing = com.travonet.wireguard.core.CoreRouter.route(activeProf.rawConfig, protocolDelegations)
                    if (routing.targetCore != com.travonet.wireguard.core.CoreType.TRAVONET_WG) {
                        if (!com.travonet.wireguard.core.CoreManager.isInstalled(context, routing.targetCore)) {
                            Toast.makeText(
                                context,
                                "Для запуска ${routing.detectedProtocol} необходимо установить ядро ${routing.targetCore.title} во вкладке «Ядра»",
                                Toast.LENGTH_LONG
                            ).show()
                            scope.launch { pagerState.animateScrollToPage(2) }
                            return@BottomControlBar
                        }
                    }
                    onRequestStartTunnel(activeProf, activeFallbackStrategy, tunnelMode)
                },
                onStopClick = {
                    TunnelManager.stop(context)
                },
                onPingClick = {
                    pingSelectedProfile()
                },
                isPinging = isPingingBottom,
                pingLatency = bottomPingLatency
            )
        }
    ) { innerPadding ->
        HorizontalPager(
            state = pagerState,
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) { page ->
            when (page) {
                0 -> ConfigsScreen(
                    profiles = profiles,
                    subscriptions = subscriptions,
                    selectedProfileId = selectedProfileId,
                    fallbackStrategy = activeFallbackStrategy,
                    showAddresses = showAddresses,
                    pingResults = pingResults,
                    isTestingAll = isTestingAll,
                    onPingAllProfiles = { pingAllProfiles() },
                    onPingProfiles = { subset -> pingProfilesSubset(subset) },
                    onSelectProfile = { id ->
                        selectedProfileId = id
                        repository.setSelectedProfileId(id)
                        val curState = TunnelManager.state.value
                        if (curState.status == com.travonet.wireguard.model.TunnelStatus.CONNECTED && curState.profileId != id) {
                            val newProf = profiles.firstOrNull { it.id == id }
                            if (newProf != null) {
                                onRequestStartTunnel(newProf, activeFallbackStrategy, tunnelMode)
                            }
                        }
                    },
                    onAddOrUpdateProfile = { newProf ->
                        repository.addOrUpdateProfile(newProf)
                        profiles = repository.getProfiles()
                    },
                    onDeleteProfile = { id ->
                        repository.deleteProfile(id)
                        profiles = repository.getProfiles()
                        selectedProfileId = repository.getSelectedProfileId()
                    },
                    onDeleteSubscription = { url -> deleteSubscription(url) },
                    onGenerateWarp = { generateWarp() },
                    onOpenAddManual = { isAddingProfile = true },
                    onPasteFromClipboard = { pasteFromClipboard() },
                    onImportFromFile = { filePickerLauncher.launch("*/*") },
                    onOpenSubscription = { showSubscriptionDialog = true },
                    hasSubscription = subscriptions.isNotEmpty() || subscriptionUrl.isNotBlank(),
                    onUpdateSubscription = {
                        val targetUrl = subscriptions.firstOrNull()?.url ?: subscriptionUrl
                        if (targetUrl.isNotBlank()) fetchSubscription(targetUrl)
                    },
                    onUpdateSpecificSubscription = { url -> fetchSubscription(url) },
                    updatingSubscriptionUrls = updatingSubscriptionUrls,
                    isUpdatingSubscription = isFetchingSubscription,
                    customDelegations = protocolDelegations
                )

                1 -> StrategiesScreen(
                    strategies = strategies,
                    selectedStrategyId = selectedStrategyId,
                    onSelectStrategy = { id ->
                        selectedStrategyId = id
                        repository.setSelectedStrategyId(id)
                    },
                    onAddOrUpdateStrategy = { newStrat ->
                        repository.addOrUpdateCustomStrategy(newStrat)
                        strategies = repository.getStrategies()
                    },
                    onDeleteStrategy = { id ->
                        repository.deleteCustomStrategy(id)
                        strategies = repository.getStrategies()
                        selectedStrategyId = repository.getSelectedStrategyId()
                    }
                )

                2 -> CoresScreen(
                    coreManager = coreManager,
                    onDelegationsChanged = { protocolDelegations = it }
                )
            }
        }
    }

    if (showSettingsDialog) {
        AppSettingsDialog(
            currentSocksAddr = socksAddr,
            currentRelayMode = warpRelayMode,
            customRelayUrl = warpRelayUrl,
            customRelayToken = warpRelayToken,
            builtInRelayUrl = repository.getBuiltInWarpRelayUrl(),
            isForegroundService = repository.isForegroundServiceEnabled(),
            isWakeLock = repository.isWakeLockEnabled(),
            isAutoReconnect = repository.isAutoReconnectEnabled(),
            isShowAddresses = showAddresses,
            currentDnsPreset = repository.getDnsPreset(),
            currentCustomDns = repository.getCustomDns(),
            isOverrideDns = repository.isOverrideDns(),
            onDismiss = { showSettingsDialog = false },
            onSave = { newSocksAddr, relayMode, relayUrl, relayToken, fgService, wakeLock, autoReconnect, newShowAddresses, dnsPreset, customDns, overrideDns ->
                socksAddr = newSocksAddr
                repository.setSocksListenAddr(newSocksAddr)
                repository.saveWarpRelaySettings(relayMode, relayUrl, relayToken)
                repository.setForegroundServiceEnabled(fgService)
                repository.setWakeLockEnabled(wakeLock)
                repository.setAutoReconnectEnabled(autoReconnect)
                repository.setShowAddressesEnabled(newShowAddresses)
                repository.setDnsPreset(dnsPreset)
                repository.setCustomDns(customDns)
                repository.setOverrideDns(overrideDns)
                showAddresses = newShowAddresses
                warpRelayMode = repository.getWarpRelayMode()
                warpRelayUrl = repository.getWarpRelayUrl()
                warpRelayToken = repository.getWarpRelayToken()
                showSettingsDialog = false

                Toast.makeText(
                    context,
                    "Настройки сохранены",
                    Toast.LENGTH_SHORT
                ).show()
            }
        )
    }

    if (showInfoDialog) {
        val nativeVer = try {
            GoBackend.wgVersion() ?: "TravonetWG-go (Unknown)"
        } catch (e: Throwable) {
            "Ошибка JNI: ${e.message}"
        }

        AlertDialog(
            onDismissRequest = { showInfoDialog = false },
            title = { Text("О приложении TravonetVPN") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "TravonetVPN — универсальный клиент VPN и прокси со встроенной десинхронизацией пакетов для обхода глубокого анализа ТСПУ / DPI и поддержкой современных протоколов.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    HorizontalDivider()
                    Text(
                        text = "• Режим VPN: системный TUN интерфейс (маршрутизирует весь интернет).\n• Режим SOCKS5: локальный прокси без прав VPN на $socksAddr.\n• Десинхронизация: если в конфигурации не указана Strategy, используется выбранная во второй вкладке.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    HorizontalDivider()
                    Text(
                        text = "Версия ядра: $nativeVer",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showInfoDialog = false }) {
                    Text("Понятно")
                }
            }
        )
    }

    if (isAddingProfile) {
        AddEditProfileDialog(
            profile = null,
            onGenerateWarp = { generateWarp() },
            onDismiss = { isAddingProfile = false },
            onSave = { newProfile ->
                repository.addOrUpdateProfile(newProfile)
                profiles = repository.getProfiles()
                selectedProfileId = newProfile.id
                repository.setSelectedProfileId(newProfile.id)
                isAddingProfile = false
                Toast.makeText(context, "Конфигурация сохранена", Toast.LENGTH_SHORT).show()
            }
        )
    }

    warpUiState?.let { state ->
        WarpProgressDialog(
            state = state,
            relayConfigured = warpRelayUrl.isNotBlank(),
            onDismiss = { warpUiState = null },
            onRetry = { generateWarp() },
            onConfigureRelay = {
                warpUiState = null
                showWarpRelayDialog = true
            }
        )
    }

    if (showWarpRelayDialog) {
        WarpRelayDialog(
            currentUrl = warpRelayUrl,
            currentToken = warpRelayToken,
            onSave = { url, token ->
                repository.setWarpRelayUrl(url)
                repository.setWarpRelayToken(token)
                warpRelayMode = repository.getWarpRelayMode()
                warpRelayUrl = repository.getWarpRelayUrl()
                warpRelayToken = repository.getWarpRelayToken()
                showWarpRelayDialog = false
                Toast.makeText(
                    context,
                    if (url.isBlank()) "Релей WARP отключён" else "Релей WARP сохранён",
                    Toast.LENGTH_SHORT
                ).show()
            },
            onDismiss = { showWarpRelayDialog = false }
        )
    }

    if (showSubscriptionDialog) {
        SubscriptionDialog(
            initialUrl = subscriptionUrl,
            onDismiss = {
                if (!isFetchingSubscription) {
                    showSubscriptionDialog = false
                    subscriptionErrorMessage = null
                }
            },
            onFetch = { url ->
                fetchSubscription(url)
            },
            isLoading = isFetchingSubscription,
            errorMessage = subscriptionErrorMessage
        )
    }

    if (showAddFreeTurnDialog) {
        AddFreeTurnDialog(
            onDismiss = { showAddFreeTurnDialog = false },
            onSave = { newProf ->
                repository.addOrUpdateProfile(newProf)
                profiles = repository.getProfiles()
                showAddFreeTurnDialog = false
                Toast.makeText(context, "Профиль FreeTURN сохранен", Toast.LENGTH_SHORT).show()
            }
        )
    }

    if (captchaUrl != null) {
        CaptchaDialog(
            url = captchaUrl!!,
            onDismiss = { TunnelManager.hideCaptcha() }
        )
    }
}

@Composable
private fun AddConfigMenuButton(
    onPasteFromClipboard: () -> Unit,
    onImportFromFile: () -> Unit,
    onGenerateWarp: () -> Unit,
    onCreateManual: () -> Unit,
    onOpenSubscription: () -> Unit,
    onOpenFreeTurn: () -> Unit,
    onUpdateSubscription: (() -> Unit)? = null
) {
    var expanded by remember { mutableStateOf(false) }
    val rotation by animateFloatAsState(
        targetValue = if (expanded) 45f else 0f,
        animationSpec = tween(durationMillis = 150, easing = FastOutSlowInEasing),
        label = "plus_rotation"
    )

    Box {
        IconButton(onClick = { expanded = !expanded }) {
            Icon(
                imageVector = Icons.Default.Add,
                contentDescription = "Добавить конфигурацию",
                modifier = Modifier.graphicsLayer { rotationZ = rotation }
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            DropdownMenuItem(
                text = { Text("Вставить из буфера") },
                leadingIcon = {
                    Icon(Icons.Default.ContentPaste, contentDescription = null)
                },
                onClick = {
                    expanded = false
                    onPasteFromClipboard()
                }
            )
            DropdownMenuItem(
                text = { Text("Добавить подписку (URL)") },
                leadingIcon = {
                    Icon(Icons.Default.CloudDownload, contentDescription = null)
                },
                onClick = {
                    expanded = false
                    onOpenSubscription()
                }
            )
            if (onUpdateSubscription != null) {
                DropdownMenuItem(
                    text = { Text("Обновить подписку") },
                    leadingIcon = {
                        Icon(Icons.Default.Sync, contentDescription = null)
                    },
                    onClick = {
                        expanded = false
                        onUpdateSubscription()
                    }
                )
            }
            DropdownMenuItem(
                text = { Text("Импорт из файла") },
                leadingIcon = {
                    Icon(Icons.Default.FileOpen, contentDescription = null)
                },
                onClick = {
                    expanded = false
                    onImportFromFile()
                }
            )
            DropdownMenuItem(
                text = { Text("Сгенерировать WARP") },
                leadingIcon = {
                    Icon(Icons.Default.Cloud, contentDescription = null)
                },
                onClick = {
                    expanded = false
                    onGenerateWarp()
                }
            )
            DropdownMenuItem(
                text = { Text("Создать вручную") },
                leadingIcon = {
                    Icon(Icons.Default.Add, contentDescription = null)
                },
                onClick = {
                    expanded = false
                    onCreateManual()
                }
            )
        }
    }
}
