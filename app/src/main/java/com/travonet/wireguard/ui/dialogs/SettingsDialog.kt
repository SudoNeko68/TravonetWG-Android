package com.travonet.wireguard.ui.dialogs

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.travonet.wireguard.model.DnsMode
import com.travonet.wireguard.model.WarpRelayMode

/**
 * Общие настройки приложения: SOCKS5, источник релея для регистрации WARP,
 * параметры foreground службы, wakelock, автопереподключения и батареи.
 */
@Composable
fun AppSettingsDialog(
    currentSocksAddr: String,
    currentRelayMode: WarpRelayMode,
    customRelayUrl: String,
    customRelayToken: String,
    builtInRelayUrl: String,
    isForegroundService: Boolean,
    isWakeLock: Boolean,
    isAutoReconnect: Boolean,
    isShowAddresses: Boolean,
    currentDnsPreset: String = "cloudflare",
    currentCustomDns: String = "1.1.1.1, 8.8.8.8",
    currentDnsMode: DnsMode = DnsMode.CUSTOM,
    currentCustomDnsType: String = "DOH",
    currentCustomDnsUdp: String = "1.1.1.1, 1.0.0.1",
    currentCustomDnsDot: String = "tls://1.1.1.1:853",
    currentCustomDnsDoh: String = "https://1.1.1.1/dns-query",
    currentCustomHosts: String = "",
    onDismiss: () -> Unit,
    onSave: (
        socksAddr: String,
        mode: WarpRelayMode,
        url: String,
        token: String,
        foregroundService: Boolean,
        wakeLock: Boolean,
        autoReconnect: Boolean,
        showAddresses: Boolean,
        dnsPreset: String,
        customDns: String,
        dnsMode: DnsMode,
        customDnsType: String,
        customDnsUdp: String,
        customDnsDot: String,
        customDnsDoh: String,
        customHosts: String
    ) -> Unit
) {
    var socksAddr by remember { mutableStateOf(currentSocksAddr) }
    var relayMode by remember { mutableStateOf(currentRelayMode) }
    var relayUrl by remember { mutableStateOf(customRelayUrl) }
    var relayToken by remember { mutableStateOf(customRelayToken) }
    var foregroundService by remember { mutableStateOf(isForegroundService) }
    var wakeLock by remember { mutableStateOf(isWakeLock) }
    var autoReconnect by remember { mutableStateOf(isAutoReconnect) }
    var showAddresses by remember { mutableStateOf(isShowAddresses) }
    var dnsPreset by remember { mutableStateOf(currentDnsPreset) }
    var customDns by remember { mutableStateOf(currentCustomDns) }
    var dnsMode by remember { mutableStateOf(currentDnsMode) }
    var customDnsType by remember { mutableStateOf(currentCustomDnsType) }
    var customDnsUdp by remember { mutableStateOf(currentCustomDnsUdp) }
    var customDnsDot by remember { mutableStateOf(currentCustomDnsDot) }
    var customDnsDoh by remember { mutableStateOf(currentCustomDnsDoh) }
    var customHosts by remember { mutableStateOf(currentCustomHosts) }
    var showCustomDnsConfigDialog by remember { mutableStateOf(false) }

    val context = LocalContext.current
    val powerManager = remember { context.getSystemService(Context.POWER_SERVICE) as? PowerManager }
    var isIgnoringBatteryOptimizations by remember {
        mutableStateOf(
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                powerManager?.isIgnoringBatteryOptimizations(context.packageName) == true
            } else {
                true
            }
        )
    }

    val customRelayValid = relayMode != WarpRelayMode.CUSTOM || relayUrl.isNotBlank()
    val customDnsValid = dnsMode != DnsMode.CUSTOM || dnsPreset != "custom" || customDns.isNotBlank()
    val canSave = socksAddr.isNotBlank() && customRelayValid && customDnsValid

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Настройки") },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 520.dp)
                    .verticalScroll(rememberScrollState())
                    .imePadding(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "SOCKS5",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                OutlinedTextField(
                    value = socksAddr,
                    onValueChange = { socksAddr = it },
                    label = { Text("IP:Порт локального прокси") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Text(
                    text = "По умолчанию 127.0.0.1:1080. Для доступа из локальной сети — 0.0.0.0:1080.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                HorizontalDivider(Modifier.padding(vertical = 2.dp))

                Text(
                    text = "Служба и надёжность соединения",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )

                SettingsSwitchRow(
                    title = "Уведомление службы (Foreground)",
                    subtitle = "Постоянное уведомление со статистикой трафика. Предотвращает выгрузку приложения системой.",
                    checked = foregroundService,
                    onCheckedChange = { foregroundService = it }
                )

                SettingsSwitchRow(
                    title = "Удержание WakeLock",
                    subtitle = "Предотвращает глубокий сон процессора во время активного VPN (может влиять на расход батареи).",
                    checked = wakeLock,
                    onCheckedChange = { wakeLock = it }
                )

                SettingsSwitchRow(
                    title = "Автоперезапуск при сбое",
                    subtitle = "Автоматически переподключать туннель при потере handshake или смене сети.",
                    checked = autoReconnect,
                    onCheckedChange = { autoReconnect = it }
                )

                SettingsSwitchRow(
                    title = "Пропуск оптимизации батареи",
                    subtitle = if (isIgnoringBatteryOptimizations) {
                        "Исключение активно (система не усыпляет VPN)."
                    } else {
                        "Ограничена системой (может обрывать связь в фоне)."
                    },
                    checked = isIgnoringBatteryOptimizations,
                    onCheckedChange = { checked ->
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                            try {
                                if (checked) {
                                    val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                                        data = Uri.parse("package:${context.packageName}")
                                    }
                                    context.startActivity(intent)
                                } else {
                                    val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                                    context.startActivity(intent)
                                }
                            } catch (_: Exception) {
                                try {
                                    context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                                } catch (_: Exception) {}
                            }
                        }
                    }
                )

                HorizontalDivider(Modifier.padding(vertical = 2.dp))

                Text(
                    text = "Отображение",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )

                SettingsSwitchRow(
                    title = "Предпросмотр адресов",
                    subtitle = "Отображать IP-адрес и Endpoint в карточках конфигураций.",
                    checked = showAddresses,
                    onCheckedChange = { showAddresses = it }
                )

                HorizontalDivider(Modifier.padding(vertical = 2.dp))

                Text(
                    text = "Режим DNS",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )

                RelayModeRow(
                    title = "Системный DNS",
                    subtitle = "Использовать DNS от сети Wi-Fi / оператора связи (запросы не перехватываются)",
                    selected = dnsMode == DnsMode.SYSTEM,
                    enabled = true,
                    onClick = { dnsMode = DnsMode.SYSTEM }
                )

                RelayModeRow(
                    title = "DNS через VPN",
                    subtitle = "Безопасный DNS внутри туннеля (из профиля WireGuard или DoH через прокси)",
                    selected = dnsMode == DnsMode.SERVER,
                    enabled = true,
                    onClick = { dnsMode = DnsMode.SERVER }
                )

                RelayModeRow(
                    title = "Свой DNS",
                    subtitle = "Выбрать публичный DNS резолвер или настроить собственный UDP, DoT, DoH и hosts",
                    selected = dnsMode == DnsMode.CUSTOM,
                    enabled = true,
                    onClick = { dnsMode = DnsMode.CUSTOM },
                    trailingContent = {
                        IconButton(
                            onClick = {
                                dnsMode = DnsMode.CUSTOM
                                showCustomDnsConfigDialog = true
                            }
                        ) {
                            Icon(
                                imageVector = Icons.Default.Settings,
                                contentDescription = "Настройки своего DNS",
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                )

                if (dnsMode == DnsMode.CUSTOM) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "Провайдер DNS:",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.primary
                    )
                    RelayModeRow(
                        title = "Cloudflare (1.1.1.1)",
                        subtitle = "1.1.1.1, 1.0.0.1 (DoH https://1.1.1.1/dns-query)",
                        selected = dnsPreset == "cloudflare",
                        enabled = true,
                        onClick = { dnsPreset = "cloudflare" }
                    )
                    RelayModeRow(
                        title = "Google (8.8.8.8)",
                        subtitle = "8.8.8.8, 8.8.4.4 (DoH https://dns.google/dns-query)",
                        selected = dnsPreset == "google",
                        enabled = true,
                        onClick = { dnsPreset = "google" }
                    )
                    RelayModeRow(
                        title = "AdGuard DNS",
                        subtitle = "94.140.14.14 (DoH с блокировкой рекламы и трекеров)",
                        selected = dnsPreset == "adguard",
                        enabled = true,
                        onClick = { dnsPreset = "adguard" }
                    )
                    RelayModeRow(
                        title = "Quad9",
                        subtitle = "9.9.9.9 (DoH с защитой от фишинга и вредоносных сайтов)",
                        selected = dnsPreset == "quad9",
                        enabled = true,
                        onClick = { dnsPreset = "quad9" }
                    )
                    RelayModeRow(
                        title = "Произвольный DNS",
                        subtitle = "Тонкая настройка: UDP, DoT, DoH и hosts",
                        selected = dnsPreset == "custom",
                        enabled = true,
                        onClick = {
                            dnsPreset = "custom"
                            showCustomDnsConfigDialog = true
                        },
                        trailingContent = {
                            IconButton(
                                onClick = {
                                    dnsPreset = "custom"
                                    showCustomDnsConfigDialog = true
                                }
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Settings,
                                    contentDescription = "Настройки своего DNS",
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    )

                    if (dnsPreset == "custom") {
                        OutlinedTextField(
                            value = customDns,
                            onValueChange = { customDns = it },
                            label = { Text("DNS серверы") },
                            placeholder = { Text("1.1.1.1, 8.8.8.8 или https://...") },
                            singleLine = true,
                            isError = customDns.isBlank(),
                            supportingText = {
                                if (customDns.isBlank()) {
                                    Text("Введите хотя бы один IP-адрес или DoH URL")
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }

                HorizontalDivider(Modifier.padding(vertical = 2.dp))

                Text(
                    text = "Релей регистрации WARP",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Через релей уходит только публичный ключ. Приватный ключ генерируется на телефоне и не покидает его.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                RelayModeRow(
                    title = "Встроенный в сборку",
                    subtitle = if (builtInRelayUrl.isBlank()) {
                        "В этой сборке релей не задан"
                    } else {
                        builtInRelayUrl
                    },
                    selected = relayMode == WarpRelayMode.AUTO,
                    enabled = builtInRelayUrl.isNotBlank(),
                    onClick = { relayMode = WarpRelayMode.AUTO }
                )

                RelayModeRow(
                    title = "Свой релей",
                    subtitle = "Указать URL и токен вручную",
                    selected = relayMode == WarpRelayMode.CUSTOM,
                    enabled = true,
                    onClick = {
                        relayMode = WarpRelayMode.CUSTOM
                        if (relayUrl.isBlank()) relayUrl = builtInRelayUrl
                    }
                )

                if (relayMode == WarpRelayMode.CUSTOM) {
                    OutlinedTextField(
                        value = relayUrl,
                        onValueChange = { relayUrl = it },
                        label = { Text("URL релея") },
                        placeholder = { Text("https://relay.example/register") },
                        singleLine = true,
                        isError = relayUrl.isBlank(),
                        supportingText = {
                            if (relayUrl.isBlank()) {
                                Text("Введите URL или выберите «Без релея»")
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = relayToken,
                        onValueChange = { relayToken = it },
                        label = { Text("Токен") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                RelayModeRow(
                    title = "Без релея",
                    subtitle = "Прямая регистрация в Cloudflare (может блокироваться провайдером)",
                    selected = relayMode == WarpRelayMode.NONE,
                    enabled = true,
                    onClick = { relayMode = WarpRelayMode.NONE }
                )

                Spacer(Modifier.height(2.dp))
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onSave(
                        socksAddr.trim(),
                        relayMode,
                        relayUrl.trim(),
                        relayToken.trim(),
                        foregroundService,
                        wakeLock,
                        autoReconnect,
                        showAddresses,
                        dnsPreset,
                        customDns.trim(),
                        dnsMode,
                        customDnsType,
                        customDnsUdp.trim(),
                        customDnsDot.trim(),
                        customDnsDoh.trim(),
                        customHosts.trim()
                    )
                },
                enabled = canSave
            ) {
                Text("Сохранить")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена")
            }
        }
    )

    if (showCustomDnsConfigDialog) {
        CustomDnsConfigDialog(
            initialType = customDnsType,
            initialUdp = customDnsUdp,
            initialDot = customDnsDot,
            initialDoh = customDnsDoh,
            initialHosts = customHosts,
            onDismiss = { showCustomDnsConfigDialog = false },
            onApply = { type, udp, dot, doh, hosts ->
                customDnsType = type
                customDnsUdp = udp
                customDnsDot = dot
                customDnsDoh = doh
                customHosts = hosts
                dnsMode = DnsMode.CUSTOM
                dnsPreset = "custom"
                customDns = when (type) {
                    "UDP" -> udp
                    "DOT" -> dot
                    else -> doh
                }
                showCustomDnsConfigDialog = false
            }
        )
    }
}

@Composable
fun CustomDnsConfigDialog(
    initialType: String,
    initialUdp: String,
    initialDot: String,
    initialDoh: String,
    initialHosts: String,
    onDismiss: () -> Unit,
    onApply: (type: String, udp: String, dot: String, doh: String, hosts: String) -> Unit
) {
    var prefType by remember { mutableStateOf(if (initialType in listOf("UDP", "DOT", "DOH")) initialType else "DOH") }
    var udpText by remember { mutableStateOf(initialUdp) }
    var dotText by remember { mutableStateOf(initialDot) }
    var dohText by remember { mutableStateOf(initialDoh) }
    var hostsText by remember { mutableStateOf(initialHosts) }

    val context = LocalContext.current
    val hostsFilePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            try {
                val content = context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                if (content != null) {
                    hostsText = content
                    Toast.makeText(context, "Файл hosts загружен (${content.lines().size} строк)", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Ошибка чтения файла: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Настройки DNS") },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 500.dp)
                    .verticalScroll(rememberScrollState())
                    .imePadding(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Предпочитаемый тип протокола:",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChip(
                        selected = prefType == "DOH",
                        onClick = { prefType = "DOH" },
                        label = { Text("DoH") }
                    )
                    FilterChip(
                        selected = prefType == "DOT",
                        onClick = { prefType = "DOT" },
                        label = { Text("DoT") }
                    )
                    FilterChip(
                        selected = prefType == "UDP",
                        onClick = { prefType = "UDP" },
                        label = { Text("UDP") }
                    )
                }

                Text(
                    text = when (prefType) {
                        "DOH" -> "DoH (DNS-over-HTTPS): шифрованный DNS поверх HTTPS, лучший обход блокировок."
                        "DOT" -> "DoT (DNS-over-TLS): шифрованный DNS через TLS на порту 853."
                        else -> "UDP: стандартный открытый DNS (минимальная задержка, но без шифрования)."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = udpText,
                    onValueChange = { udpText = it },
                    label = { Text("UDP DNS серверы (IP через запятую)") },
                    placeholder = { Text("1.1.1.1, 1.0.0.1") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = dotText,
                    onValueChange = { dotText = it },
                    label = { Text("DoT (DNS-over-TLS)") },
                    placeholder = { Text("tls://1.1.1.1:853") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = dohText,
                    onValueChange = { dohText = it },
                    label = { Text("DoH (DNS-over-HTTPS)") },
                    placeholder = { Text("https://1.1.1.1/dns-query") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                HorizontalDivider(Modifier.padding(vertical = 4.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Свой файл hosts",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Row {
                        IconButton(
                            onClick = { hostsFilePickerLauncher.launch("*/*") }
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = "Загрузить из файла")
                        }
                        if (hostsText.isNotBlank()) {
                            IconButton(
                                onClick = { hostsText = "" }
                            ) {
                                Icon(Icons.Default.Delete, contentDescription = "Очистить hosts")
                            }
                        }
                    }
                }

                Text(
                    text = "Формат: IP домен (например, 127.0.0.1 ads.com или 0.0.0.0 tracker.com для блокировки рекламы).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = hostsText,
                    onValueChange = { hostsText = it },
                    label = { Text("Правила hosts") },
                    placeholder = { Text("127.0.0.1 adservice.google.com\n0.0.0.0 telemetry.app.com") },
                    minLines = 4,
                    maxLines = 8,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onApply(prefType, udpText.trim(), dotText.trim(), dohText.trim(), hostsText.trim())
                }
            ) {
                Text("Применить")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена")
            }
        }
    )
}

@Composable
private fun RelayModeRow(
    title: String,
    subtitle: String,
    selected: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
    trailingContent: (@Composable () -> Unit)? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick)
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(
            selected = selected,
            onClick = null,
            enabled = enabled
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 4.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium,
                color = if (enabled) {
                    MaterialTheme.colorScheme.onSurface
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                }
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (trailingContent != null) {
            trailingContent()
        }
    }
}

@Composable
private fun SettingsSwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(end = 8.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange
        )
    }
}
