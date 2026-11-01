package com.travonet.wireguard.ui.dialogs

import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
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

                OutlinedTextField(
                    value = rawConfig,
                    onValueChange = {
                        rawConfig = it
                        errorMessage = null
                    },
                    label = { Text("Текст конфигурации WireGuard (.conf)") },
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
                    if (trimmed.startsWith("vpn://", ignoreCase = true)) {
                        val parsedProfile = WgConfigParser.parseProfile(
                            name = name.trim().ifBlank { "Amnezia Profile" },
                            rawConfig = trimmed,
                            id = profile?.id
                        )
                        if (!parsedProfile.rawConfig.contains("[Interface]", ignoreCase = true)) {
                            errorMessage = "Не удалось извлечь WireGuard/AmneziaWG конфигурацию из ссылки vpn://"
                            return@Button
                        }
                        onSave(parsedProfile)
                        return@Button
                    }

                    if (name.isBlank()) {
                        errorMessage = "Укажите название профиля"
                        return@Button
                    }
                    if (rawConfig.isBlank() || !rawConfig.contains("[Interface]", ignoreCase = true)) {
                        errorMessage = "Конфигурация должна содержать блок [Interface]"
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
