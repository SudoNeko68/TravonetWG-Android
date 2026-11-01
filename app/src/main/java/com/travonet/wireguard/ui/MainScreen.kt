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
import com.travonet.wireguard.model.TunnelMode
import com.travonet.wireguard.model.WarpRelayMode
import com.travonet.wireguard.model.WgProfile
import com.travonet.wireguard.parser.WgConfigParser
import com.travonet.wireguard.repository.AppRepository
import com.travonet.wireguard.service.PingHelper
import com.travonet.wireguard.service.PingResult
import com.travonet.wireguard.service.TunnelManager
import com.travonet.wireguard.ui.components.BottomControlBar
import com.travonet.wireguard.ui.dialogs.AddEditProfileDialog
import com.travonet.wireguard.ui.dialogs.AppSettingsDialog
import com.travonet.wireguard.ui.dialogs.WarpProgressDialog
import com.travonet.wireguard.ui.dialogs.WarpRelayDialog
import com.travonet.wireguard.ui.dialogs.WarpUiState
import com.travonet.wireguard.ui.screens.ConfigsScreen
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

    var selectedTab by remember { mutableIntStateOf(0) }
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
                selectedTab = 0
                Toast.makeText(context, "Конфигурация импортирована!", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(context, "Ошибка чтения файла: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
            }
        }
    }

    fun pasteFromClipboard() {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val text = clip.getItemAt(0).text?.toString() ?: ""
            val isWg = text.contains("[Interface]", ignoreCase = true)
            val isVpnUrl = text.trimStart().startsWith("vpn://", ignoreCase = true)
            if (isWg || isVpnUrl) {
                val profile = WgConfigParser.parseProfile("Профиль из буфера", text)
                repository.addOrUpdateProfile(profile)
                profiles = repository.getProfiles()
                selectedProfileId = profile.id
                repository.setSelectedProfileId(profile.id)
                selectedTab = 0
                Toast.makeText(context, "Импортировано: ${profile.name}", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(context, "Буфер обмена не содержит конфигурацию WireGuard или vpn://", Toast.LENGTH_SHORT).show()
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
                selectedTab = 0
                warpUiState = WarpUiState.Success(profile.name, profile.endpoint)
            }.onFailure { error ->
                warpUiState = WarpUiState.Failure(
                    error.message?.takeIf { it.isNotBlank() }
                        ?: "Ошибка ${error.javaClass.simpleName}"
                )
            }
        }
    }

    fun pingAllProfiles() {
        if (isTestingAll || profiles.isEmpty()) return
        isTestingAll = true
        scope.launch {
            for (profile in profiles) {
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
                                text = "TravonetWG",
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
                            onCreateManual = { isAddingProfile = true }
                        )

                        IconButton(onClick = { showInfoDialog = true }) {
                            Icon(Icons.Default.Info, contentDescription = "О программе")
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                )

                // The two top tab switchers requested by user
                PrimaryTabRow(
                    selectedTabIndex = selectedTab,
                    containerColor = MaterialTheme.colorScheme.surface
                ) {
                    Tab(
                        selected = selectedTab == 0,
                        onClick = { selectedTab = 0 },
                        text = {
                            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                Icon(Icons.Default.Dns, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Конфигурации (${profiles.size})", fontWeight = if (selectedTab == 0) FontWeight.Bold else FontWeight.Normal)
                            }
                        }
                    )

                    Tab(
                        selected = selectedTab == 1,
                        onClick = { selectedTab = 1 },
                        text = {
                            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                Icon(Icons.Default.Bolt, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Стратегии обхода", fontWeight = if (selectedTab == 1) FontWeight.Bold else FontWeight.Normal)
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
                        Toast.makeText(context, "Выберите конфигурацию WireGuard!", Toast.LENGTH_SHORT).show()
                        return@BottomControlBar
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
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            when (selectedTab) {
                0 -> ConfigsScreen(
                    profiles = profiles,
                    selectedProfileId = selectedProfileId,
                    fallbackStrategy = activeFallbackStrategy,
                    showAddresses = showAddresses,
                    pingResults = pingResults,
                    isTestingAll = isTestingAll,
                    onPingAllProfiles = { pingAllProfiles() },
                    onSelectProfile = { id ->
                        selectedProfileId = id
                        repository.setSelectedProfileId(id)
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
                    onGenerateWarp = { generateWarp() },
                    onOpenAddManual = { isAddingProfile = true },
                    onPasteFromClipboard = { pasteFromClipboard() },
                    onImportFromFile = { filePickerLauncher.launch("*/*") }
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
            onDismiss = { showSettingsDialog = false },
            onSave = { newSocksAddr, relayMode, relayUrl, relayToken, fgService, wakeLock, autoReconnect, newShowAddresses ->
                socksAddr = newSocksAddr
                repository.setSocksListenAddr(newSocksAddr)
                repository.saveWarpRelaySettings(relayMode, relayUrl, relayToken)
                repository.setForegroundServiceEnabled(fgService)
                repository.setWakeLockEnabled(wakeLock)
                repository.setAutoReconnectEnabled(autoReconnect)
                repository.setShowAddressesEnabled(newShowAddresses)
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
            title = { Text("О приложении TravonetWG") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "TravonetWG — клиент WireGuard со встроенной L3/L4 десинхронизацией пакетов для обхода глубокого анализа ТСПУ / DPI.",
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
}

@Composable
private fun AddConfigMenuButton(
    onPasteFromClipboard: () -> Unit,
    onImportFromFile: () -> Unit,
    onGenerateWarp: () -> Unit,
    onCreateManual: () -> Unit
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
