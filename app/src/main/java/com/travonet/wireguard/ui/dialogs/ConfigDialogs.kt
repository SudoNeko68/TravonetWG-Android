package com.travonet.wireguard.ui.dialogs

import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONObject
import java.util.Base64
import java.util.UUID
import com.travonet.wireguard.model.WgProfile
import com.travonet.wireguard.parser.WgConfigParser

@Composable
fun AddEditProfileDialog(
    profile: WgProfile? = null,
    onGenerateWarp: (() -> Unit)? = null,
    onDismiss: () -> Unit,
    onSave: (WgProfile) -> Unit
) {
    val context = LocalContext.current
    var name by remember { mutableStateOf(profile?.name ?: "Новая конфигурация") }
    var rawConfig by remember(profile?.id) {
        mutableStateOf(profile?.rawConfig ?: "")
    }

    var errorMessage by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(if (profile == null) "Добавить конфигурацию" else "Редактировать конфигурацию")
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Название профиля") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = cm.primaryClip
                            if (clip != null && clip.itemCount > 0) {
                                val pasteText = clip.getItemAt(0).text?.toString() ?: ""
                                if (pasteText.isNotBlank()) {
                                    rawConfig = pasteText
                                    Toast.makeText(context, "Вставлено из буфера", Toast.LENGTH_SHORT).show()
                                }
                            }
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Из буфера", fontSize = 12.sp)
                    }

                    if (profile == null && onGenerateWarp != null) {
                        FilledTonalButton(
                            onClick = {
                                onDismiss()
                                onGenerateWarp()
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Cloud, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("WARP", fontSize = 12.sp)
                        }
                    }
                }

                val isFreeTurn = rawConfig.contains("freeturn://", ignoreCase = true) ||
                        (rawConfig.startsWith("{") && (rawConfig.contains("\"provider\"") || rawConfig.contains("\"vk\"")))

                if (isFreeTurn) {
                    var vkLinkField by remember(rawConfig) {
                        val extracted = if (rawConfig.startsWith("{")) {
                            try {
                                val obj = JSONObject(rawConfig)
                                val vk = obj.optJSONObject("vk")
                                val links = vk?.optJSONArray("links")
                                if (links != null && links.length() > 0) links.optString(0) else obj.optString("vk", "")
                            } catch (_: Exception) { "" }
                        } else if (rawConfig.startsWith("freeturn://", ignoreCase = true)) {
                            val b64 = rawConfig.substring("freeturn://".length).substringBefore(" ").trim()
                            try {
                                val decoded = String(android.util.Base64.decode(b64, android.util.Base64.URL_SAFE or android.util.Base64.DEFAULT))
                                JSONObject(decoded).optString("vk", "")
                            } catch (_: Exception) { "" }
                        } else ""
                        mutableStateOf(extracted)
                    }

                    OutlinedTextField(
                        value = vkLinkField,
                        onValueChange = { newVk ->
                            vkLinkField = newVk
                            if (rawConfig.startsWith("{")) {
                                try {
                                    val root = JSONObject(rawConfig)
                                    val vk = root.optJSONObject("vk") ?: JSONObject().also { root.put("vk", it) }
                                    vk.put("links", org.json.JSONArray().put(newVk.trim()))
                                    rawConfig = root.toString(2)
                                } catch (_: Exception) {}
                            }
                        },
                        label = { Text("Ссылка на звонок VK") },
                        placeholder = { Text("https://vk.ru/call/join/...") },
                        trailingIcon = {
                            IconButton(onClick = {
                                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = cm.primaryClip
                                if (clip != null && clip.itemCount > 0) {
                                    val t = clip.getItemAt(0).text?.toString()?.trim() ?: ""
                                    if (t.isNotBlank()) {
                                        vkLinkField = t
                                        if (rawConfig.startsWith("{")) {
                                            try {
                                                val root = JSONObject(rawConfig)
                                                val vk = root.optJSONObject("vk") ?: JSONObject().also { root.put("vk", it) }
                                                vk.put("links", org.json.JSONArray().put(t))
                                                rawConfig = root.toString(2)
                                            } catch (_: Exception) {}
                                        }
                                    }
                                }
                            }) {
                                Icon(Icons.Default.ContentPaste, contentDescription = "Вставить ссылку VK")
                            }
                        },
                        supportingText = {
                            Text("Отдельное поле для ссылки на звонок VK")
                        },
                        modifier = Modifier.fillMaxWidth(),
                        maxLines = 2
                    )
                }

                OutlinedTextField(
                    value = rawConfig,
                    onValueChange = {
                        rawConfig = it
                        errorMessage = null
                    },
                    label = { Text(if (rawConfig.startsWith("{")) "Текст конфигурации JSON" else "Текст конфигурации WireGuard (.conf)") },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(240.dp),
                    textStyle = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp
                    ),
                    isError = errorMessage != null
                )

                if (errorMessage != null) {
                    Text(
                        text = errorMessage!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                Text(
                    text = "Подсказка: если в [Interface] не указана строка Strategy = ..., будет использована стратегия из вкладки «Стратегии обхода».",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val trimmed = rawConfig.trim()
                    val httpRegex = Regex("""https?://[^\s"'<>]+""", RegexOption.IGNORE_CASE)
                    val vpnRegex = Regex("""vpn://[^\s"'<>]+""", RegexOption.IGNORE_CASE)

                    if (httpRegex.containsMatchIn(trimmed) && !trimmed.contains("[Interface]", ignoreCase = true)) {
                        errorMessage = "Это ссылка на подписку. Используйте кнопку «Добавить подписку» в меню или вставьте её из буфера обмена на главном экране."
                        return@Button
                    }

                    val vpnMatch = vpnRegex.find(trimmed)
                    if (vpnMatch != null && !trimmed.contains("[Interface]", ignoreCase = true)) {
                        val parsedProfile = WgConfigParser.parseProfile(
                            name = name.trim().ifBlank { "Amnezia Profile" },
                            rawConfig = vpnMatch.value.trim().trimEnd('.', ',', ';'),
                            id = profile?.id
                        )
                        if (!parsedProfile.rawConfig.contains("[Interface]", ignoreCase = true)) {
                            errorMessage = "Не удалось извлечь WireGuard/AmneziaWG конфигурацию из ссылки vpn://"
                            return@Button
                        }
                        onSave(parsedProfile)
                        return@Button
                    }

                    // Support all proxy links (VLESS, VMess, Trojan, SS, TUIC, Hysteria 2, ShadowTLS, WireGuard, AmneziaWG)
                    if (com.travonet.wireguard.parser.ProxyLinkParser.isProxyLink(trimmed)) {
                        val parsed = com.travonet.wireguard.parser.ProxyLinkParser.parse(
                            rawUri = trimmed,
                            fallbackName = name.trim().ifBlank { "Прокси конфигурация" },
                            subUrl = profile?.subscriptionUrl,
                            id = profile?.id
                        )
                        if (parsed != null) {
                            onSave(parsed)
                            return@Button
                        } else {
                            errorMessage = "Не удалось разобрать ссылку подключения"
                            return@Button
                        }
                    }

                    if (name.isBlank()) {
                        errorMessage = "Укажите название профиля"
                        return@Button
                    }

                    if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
                        try {
                            val obj = JSONObject(trimmed)
                            val cleanConfig = if (com.travonet.wireguard.core.CoreRouter.route(trimmed).targetCore == com.travonet.wireguard.core.CoreType.FREETURN) {
                                com.travonet.wireguard.parser.ProxyConfigSynthesizer.buildFreeTurn(trimmed)
                            } else {
                                trimmed
                            }
                            val profToSave = WgProfile(
                                id = profile?.id ?: UUID.randomUUID().toString(),
                                name = name.trim().ifBlank { "JSON Конфигурация" },
                                rawConfig = cleanConfig,
                                endpoint = profile?.endpoint ?: obj.optString("peer", ""),
                                address = profile?.address ?: "Proxy JSON",
                                allowedIps = profile?.allowedIps ?: "0.0.0.0/0, ::/0",
                                subscriptionUrl = profile?.subscriptionUrl
                            )
                            onSave(profToSave)
                            return@Button
                        } catch (e: Exception) {
                            errorMessage = "Ошибка формата JSON: ${e.message}"
                            return@Button
                        }
                    }

                    if (rawConfig.isBlank() || !rawConfig.contains("[Interface]", ignoreCase = true)) {
                        errorMessage = "Конфигурация должна содержать блок [Interface], JSON или ссылку (vless://, hysteria2://, vmess://, wg://...)"
                        return@Button
                    }

                    val parsed = WgConfigParser.parse(rawConfig)
                    if (parsed.iface.privateKey.isBlank()) {
                        errorMessage = "Укажите PrivateKey в блоке [Interface]"
                        return@Button
                    }

                    try {
                        val privBytes = android.util.Base64.decode(parsed.iface.privateKey, android.util.Base64.DEFAULT)
                        if (privBytes == null || privBytes.size != 32) {
                            errorMessage = "PrivateKey должен быть 32-байтным ключом в base64 (44 символа)"
                            return@Button
                        }
                    } catch (e: Exception) {
                        errorMessage = "Некорректный base64 формат в PrivateKey"
                        return@Button
                    }

                    for (peer in parsed.peers) {
                        if (peer.publicKey.isNotBlank()) {
                            try {
                                val pubBytes = android.util.Base64.decode(peer.publicKey, android.util.Base64.DEFAULT)
                                if (pubBytes == null || pubBytes.size != 32) {
                                    errorMessage = "PublicKey пира должен быть 32-байтным ключом в base64"
                                    return@Button
                                }
                            } catch (e: Exception) {
                                errorMessage = "Некорректный base64 формат в PublicKey"
                                return@Button
                            }
                        }
                    }

                    val updatedProfile = WgConfigParser.parseProfile(
                        name = name.trim(),
                        rawConfig = rawConfig.trim(),
                        id = profile?.id
                    )
                    onSave(updatedProfile)
                }
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
}

@Composable
fun DeleteConfirmDialog(
    title: String,
    message: String,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(message) },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) {
                Text("Удалить")
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
fun SocksSettingsDialog(
    currentAddr: String,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit
) {
    var addr by remember { mutableStateOf(currentAddr) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Настройки SOCKS5 прокси") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Локальный адрес и порт для режима Userspace SOCKS5:",
                    style = MaterialTheme.typography.bodyMedium
                )
                OutlinedTextField(
                    value = addr,
                    onValueChange = { addr = it },
                    label = { Text("IP:Порт прокси") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Text(
                    text = "По умолчанию: 127.0.0.1:1080. Для доступа из локальной сети используйте 0.0.0.0:1080.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            Button(onClick = { onSave(addr.trim()) }) {
                Text("Сохранить")
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
fun SubscriptionDialog(
    initialUrl: String = "",
    onDismiss: () -> Unit,
    onFetch: (url: String) -> Unit,
    isLoading: Boolean = false,
    errorMessage: String? = null
) {
    val context = LocalContext.current
    var urlText by remember { mutableStateOf(initialUrl) }
    var localError by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = { if (!isLoading) onDismiss() },
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.CloudDownload,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
                Spacer(Modifier.width(8.dp))
                Text("Подписка", style = MaterialTheme.typography.titleMedium)
            }
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Введите ссылку на подписку (URL). Конфигурации AmneziaWG / WireGuard будут импортированы автоматически.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = urlText,
                    onValueChange = {
                        urlText = it
                        localError = null
                    },
                    label = { Text("URL подписки (https://...)") },
                    singleLine = false,
                    maxLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isLoading,
                    isError = (localError != null || errorMessage != null)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = cm.primaryClip
                            if (clip != null && clip.itemCount > 0) {
                                val pasteText = clip.getItemAt(0).text?.toString() ?: ""
                                if (pasteText.isNotBlank()) {
                                    urlText = pasteText.trim()
                                    Toast.makeText(context, "Вставлено из буфера", Toast.LENGTH_SHORT).show()
                                }
                            }
                        },
                        enabled = !isLoading,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Из буфера", fontSize = 12.sp)
                    }
                }

                val effectiveError = localError ?: errorMessage
                if (effectiveError != null) {
                    Text(
                        text = effectiveError,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                if (isLoading) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(12.dp))
                        Text("Загрузка и парсинг...", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val trimmed = urlText.trim()
                    if (trimmed.isEmpty() || (!trimmed.startsWith("http://", ignoreCase = true) && !trimmed.startsWith("https://", ignoreCase = true))) {
                        localError = "URL должен начинаться с https:// или http://"
                        return@Button
                    }
                    onFetch(trimmed)
                },
                enabled = !isLoading
            ) {
                Text("Загрузить")
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                enabled = !isLoading
            ) {
                Text("Отмена")
            }
        }
    )
}

@Composable
fun AddFreeTurnDialog(
    initialProfile: WgProfile? = null,
    onDismiss: () -> Unit,
    onSave: (WgProfile) -> Unit
) {
    val context = LocalContext.current
    var name by remember { mutableStateOf(initialProfile?.name ?: "FreeTURN Сервер") }
    var peer by remember { mutableStateOf(initialProfile?.endpoint ?: "") }
    var vkLink by remember { mutableStateOf("") }
    var clientId by remember { mutableStateOf("") }
    var obfProfile by remember { mutableStateOf("none") }
    var obfKey by remember { mutableStateOf("") }
    var wgConfig by remember { mutableStateOf("") }
    var rawShareLink by remember { mutableStateOf(initialProfile?.rawConfig ?: "") }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    fun populateFromLink(input: String) {
        val trimmed = input.trim()
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                val obj = JSONObject(trimmed)
                val p = obj.optString("peer", "")
                val n = obj.optString("name", "")
                val cid = obj.optString("clientId", obj.optString("cid", ""))
                val obfObj = obj.optJSONObject("obf")
                val obf = obfObj?.optString("profile", "")?.ifBlank { null } ?: obj.optString("obf", "none")
                val k = obfObj?.optString("key", "")?.ifBlank { null } ?: obj.optString("key", "")
                val tunnelObj = obj.optJSONObject("tunnel")
                val wg = tunnelObj?.optString("config", "")?.ifBlank { null } ?: obj.optString("wg", "")
                val vkObj = obj.optJSONObject("vk")
                val vks = vkObj?.optJSONArray("links")
                val vk = if (vks != null && vks.length() > 0) vks.optString(0) else obj.optString("vk", "")

                if (p.isNotBlank()) peer = p
                if (n.isNotBlank()) name = n else if (p.isNotBlank() && initialProfile == null) name = "FreeTURN ($p)"
                if (obf.isNotBlank()) obfProfile = obf
                if (k.isNotBlank()) obfKey = k
                if (cid.isNotBlank()) clientId = cid
                if (wg.isNotBlank()) wgConfig = wg
                if (vk.isNotBlank()) vkLink = vk
                rawShareLink = trimmed
                Toast.makeText(context, "Параметры извлечены из конфигурации", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                errorMessage = "Ошибка разбора JSON конфигурации: ${e.message}"
            }
        } else if (trimmed.startsWith("freeturn://", ignoreCase = true)) {
            val b64 = trimmed.substring(11).substringBefore(" ").trim()
            try {
                val decoders = listOfNotNull(
                    runCatching { Base64.getUrlDecoder() }.getOrNull(),
                    runCatching { Base64.getDecoder() }.getOrNull()
                )
                var jsonStr: String? = null
                for (dec in decoders) {
                    try {
                        jsonStr = String(dec.decode(b64))
                        break
                    } catch (_: Exception) {}
                }
                if (jsonStr != null) {
                    val obj = JSONObject(jsonStr)
                    val p = obj.optString("peer", "")
                    val n = obj.optString("name", "")
                    val obf = obj.optString("obf", "none")
                    val k = obj.optString("key", "")
                    val cid = obj.optString("cid", "")
                    val wg = obj.optString("wg", "")
                    val vk = obj.optString("vk", "")
                    if (p.isNotBlank()) peer = p
                    if (n.isNotBlank()) name = n else if (p.isNotBlank() && initialProfile == null) name = "FreeTURN ($p)"
                    if (obf.isNotBlank()) obfProfile = obf
                    if (k.isNotBlank()) obfKey = k
                    if (cid.isNotBlank()) clientId = cid
                    if (wg.isNotBlank()) wgConfig = wg
                    if (vk.isNotBlank()) vkLink = vk
                    rawShareLink = trimmed
                    Toast.makeText(context, "Параметры извлечены из ссылки", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                errorMessage = "Ошибка разбора freeturn:// ссылки: ${e.message}"
            }
        } else if (trimmed.contains("[Interface]") && trimmed.contains("[Peer]")) {
            wgConfig = trimmed
            val epMatch = Regex("""Endpoint\s*=\s*([^\s]+)""").find(trimmed)
            if (epMatch != null && !epMatch.groupValues[1].startsWith("127.0.0.1")) {
                peer = epMatch.groupValues[1]
            }
            Toast.makeText(context, "Конфигурация WireGuard загружена", Toast.LENGTH_SHORT).show()
        } else if (trimmed.contains("-peer")) {
            rawShareLink = trimmed
            val pMatch = Regex("""-peer\s+([^\s]+)""").find(trimmed)
            if (pMatch != null) peer = pMatch.groupValues[1]
            val lMatch = Regex("""-(?:links?)\s+["']?([^"'\s]+)["']?""").find(trimmed)
            if (lMatch != null) vkLink = lMatch.groupValues[1]
            Toast.makeText(context, "Параметры извлечены из аргументов", Toast.LENGTH_SHORT).show()
        }
    }

    LaunchedEffect(initialProfile?.id) {
        if (initialProfile != null && initialProfile.rawConfig.isNotBlank()) {
            populateFromLink(initialProfile.rawConfig)
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initialProfile == null) "Подключение к FreeTURN" else "Редактирование FreeTURN") },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    "Подключение к существующему FreeTURN серверу через WebRTC / звонки VK.",
                    style = MaterialTheme.typography.bodySmall
                )

                OutlinedButton(
                    onClick = {
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = cm.primaryClip
                        if (clip != null && clip.itemCount > 0) {
                            val text = clip.getItemAt(0).text?.toString() ?: ""
                            populateFromLink(text)
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Вставить freeturn:// или JSON из буфера", fontSize = 12.sp)
                }

                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Название профиля") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = peer,
                    onValueChange = { peer = it },
                    label = { Text("Сервер (Peer host:port)") },
                    placeholder = { Text("185.120.x.x:56000") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    isError = peer.isBlank() && errorMessage != null
                )

                OutlinedTextField(
                    value = vkLink,
                    onValueChange = {
                        vkLink = it
                        errorMessage = null
                    },
                    label = { Text("Ссылка на звонок VK") },
                    placeholder = { Text("https://vk.ru/call/join/...") },
                    trailingIcon = {
                        IconButton(onClick = {
                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = cm.primaryClip
                            if (clip != null && clip.itemCount > 0) {
                                val t = clip.getItemAt(0).text?.toString()?.trim() ?: ""
                                if (t.isNotBlank()) {
                                    vkLink = t
                                    Toast.makeText(context, "Ссылка VK вставлена", Toast.LENGTH_SHORT).show()
                                }
                            }
                        }) {
                            Icon(Icons.Default.ContentPaste, contentDescription = "Вставить ссылку VK")
                        }
                    },
                    supportingText = {
                        Text("Ссылка на групповой звонок VK Calls для TURN-реле")
                    },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 2
                )

                OutlinedTextField(
                    value = clientId,
                    onValueChange = { clientId = it },
                    label = { Text("Client ID (опционально)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = obfProfile,
                        onValueChange = { obfProfile = it },
                        label = { Text("Обфускация") },
                        placeholder = { Text("none / rtpopus") },
                        singleLine = true,
                        modifier = Modifier.weight(1f)
                    )
                    OutlinedTextField(
                        value = obfKey,
                        onValueChange = { obfKey = it },
                        label = { Text("Ключ (hex)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f)
                    )
                }

                OutlinedTextField(
                    value = wgConfig,
                    onValueChange = { wgConfig = it },
                    label = { Text("Конфигурация WireGuard (relay.conf)") },
                    placeholder = { Text("[Interface]\nPrivateKey = ...\n[Peer]\nPublicKey = ...") },
                    maxLines = 4,
                    modifier = Modifier.fillMaxWidth()
                )

                if (errorMessage != null) {
                    Text(
                        text = errorMessage ?: "",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val cleanPeer = peer.trim()
                    if (cleanPeer.isBlank()) {
                        errorMessage = "Укажите адрес сервера (host:port)"
                        return@Button
                    }
                    val configJson = JSONObject().apply {
                        put("peer", cleanPeer)
                        put("provider", "vk")
                        if (clientId.isNotBlank()) put("clientId", clientId.trim())
                        val vk = JSONObject().apply {
                            if (vkLink.isNotBlank()) {
                                put("links", org.json.JSONArray().put(vkLink.trim()))
                            }
                            put("manualCaptcha", true)
                        }
                        put("vk", vk)
                        if (obfProfile.isNotBlank() && obfProfile != "none") {
                            val obf = JSONObject().apply {
                                put("profile", obfProfile.trim())
                                if (obfKey.isNotBlank()) put("key", obfKey.trim())
                            }
                            put("obf", obf)
                        }
                        if (wgConfig.isNotBlank()) {
                            put("wg", wgConfig.trim())
                        }
                    }

                    var profileAddress = "FreeTURN • VK"
                    if (wgConfig.isNotBlank()) {
                        try {
                            val parsed = WgConfigParser.parse(wgConfig)
                            if (parsed.iface.addresses.isNotEmpty()) {
                                profileAddress = parsed.iface.addresses.joinToString(", ")
                            }
                        } catch (_: Exception) {}
                    }

                    val synthesizedConfig = com.travonet.wireguard.parser.ProxyConfigSynthesizer.buildFreeTurn(configJson.toString())

                    val profile = WgProfile(
                        id = initialProfile?.id ?: UUID.randomUUID().toString(),
                        name = if (name.isNotBlank()) name.trim() else "FreeTURN ($cleanPeer)",
                        rawConfig = synthesizedConfig,
                        endpoint = cleanPeer,
                        address = profileAddress,
                        allowedIps = initialProfile?.allowedIps ?: "0.0.0.0/0, ::/0",
                        subscriptionUrl = initialProfile?.subscriptionUrl
                    )
                    onSave(profile)
                }
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
}

@Composable
fun CaptchaDialog(
    url: String,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Проверка VK Captcha", style = MaterialTheme.typography.titleMedium)
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Default.Close, contentDescription = "Закрыть")
                }
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(420.dp)
            ) {
                Text(
                    "Для продолжения работы FreeTURN решите капчу в окне ниже:",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                AndroidView(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    factory = { ctx ->
                        WebView(ctx).apply {
                            settings.javaScriptEnabled = true
                            settings.domStorageEnabled = true
                            settings.useWideViewPort = true
                            settings.loadWithOverviewMode = true
                            webViewClient = WebViewClient()
                            loadUrl(url)
                        }
                    },
                    update = { webView ->
                        if (webView.url != url) {
                            webView.loadUrl(url)
                        }
                    }
                )
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text("Закрыть")
            }
        }
    )
}


