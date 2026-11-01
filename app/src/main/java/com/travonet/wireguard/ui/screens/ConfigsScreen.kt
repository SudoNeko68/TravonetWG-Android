package com.travonet.wireguard.ui.screens

import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.travonet.wireguard.model.EvasionStrategy
import com.travonet.wireguard.model.Subscription
import com.travonet.wireguard.model.WgProfile
import com.travonet.wireguard.service.PingResult
import com.travonet.wireguard.ui.dialogs.AddEditProfileDialog
import com.travonet.wireguard.ui.dialogs.DeleteConfirmDialog

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConfigsScreen(
    profiles: List<WgProfile>,
    subscriptions: List<Subscription> = emptyList(),
    selectedProfileId: String?,
    fallbackStrategy: EvasionStrategy,
    showAddresses: Boolean,
    pingResults: Map<String, PingResult>,
    isTestingAll: Boolean,
    onPingAllProfiles: () -> Unit,
    onPingProfiles: (List<WgProfile>) -> Unit = {},
    onSelectProfile: (String) -> Unit,
    onAddOrUpdateProfile: (WgProfile) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onDeleteSubscription: (String) -> Unit = {},
    onGenerateWarp: () -> Unit,
    onOpenAddManual: () -> Unit,
    onPasteFromClipboard: () -> Unit,
    onImportFromFile: () -> Unit,
    onOpenSubscription: () -> Unit = {},
    hasSubscription: Boolean = false,
    onUpdateSubscription: () -> Unit = {},
    onUpdateSpecificSubscription: (String) -> Unit = {},
    updatingSubscriptionUrls: Set<String> = emptySet(),
    isUpdatingSubscription: Boolean = false,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var editingProfile by remember { mutableStateOf<WgProfile?>(null) }
    var deletingProfileId by remember { mutableStateOf<String?>(null) }
    var deletingSubscription by remember { mutableStateOf<Subscription?>(null) }

    // Standalone profiles (local, WARP, manual)
    val standaloneProfiles = remember(profiles) {
        profiles.filter { it.subscriptionUrl.isNullOrBlank() }
    }

    // Merge explicitly registered subscriptions + any discovered from profiles
    val effectiveSubscriptions = remember(subscriptions, profiles) {
        val knownUrls = subscriptions.map { it.url }.toSet()
        val orphanUrls = profiles.mapNotNull { it.subscriptionUrl }.distinct().filter { it !in knownUrls }
        if (orphanUrls.isNotEmpty()) {
            subscriptions + orphanUrls.map { u ->
                Subscription(url = u, title = extractHost(u))
            }
        } else {
            subscriptions
        }
    }

    // Determine all group IDs for expand / collapse toggles
    val allGroupKeys = remember(standaloneProfiles, effectiveSubscriptions) {
        val keys = mutableSetOf<String>()
        if (standaloneProfiles.isNotEmpty()) {
            keys.add("standalone")
        }
        effectiveSubscriptions.forEach { keys.add(it.url) }
        keys
    }

    // By default, all groups are expanded
    var expandedGroupKeys by rememberSaveable {
        mutableStateOf<Set<String>?>(null)
    }

    val currentExpanded = expandedGroupKeys ?: allGroupKeys
    val areAllExpanded = allGroupKeys.isNotEmpty() && currentExpanded.containsAll(allGroupKeys)

    Column(modifier = modifier.fillMaxSize()) {
        // Каталог конфигураций полоска с кнопками управления
        Surface(
            modifier = Modifier.fillMaxWidth(),
            color = MaterialTheme.colorScheme.surfaceVariant,
            tonalElevation = 1.dp
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Каталог конфигураций",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "Всего: ${profiles.size} ${declensionProfile(profiles.size)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (allGroupKeys.isNotEmpty()) {
                        TextButton(
                            onClick = {
                                expandedGroupKeys = if (areAllExpanded) emptySet() else allGroupKeys
                            },
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = if (areAllExpanded) "Скрыть все" else "Развернуть все",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }

                    IconButton(
                        onClick = onPingAllProfiles,
                        enabled = profiles.isNotEmpty() && !isTestingAll
                    ) {
                        if (isTestingAll) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp
                            )
                        } else {
                            Icon(
                                imageVector = Icons.Default.Speed,
                                contentDescription = "Тест скорости всех конфигураций",
                                tint = if (profiles.isNotEmpty()) {
                                    MaterialTheme.colorScheme.primary
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                }
                            )
                        }
                    }
                }
            }
        }

        if (profiles.isEmpty() && effectiveSubscriptions.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 16.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(
                        Icons.Default.Dns,
                        contentDescription = null,
                        modifier = Modifier.size(38.dp),
                        tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.6f)
                    )
                    Text(
                        text = "Нет добавленных конфигураций",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "Используйте кнопку «+» сверху или быстрые действия ниже",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(4.dp))

                    Button(
                        onClick = onGenerateWarp,
                        modifier = Modifier.fillMaxWidth(),
                        contentPadding = PaddingValues(vertical = 10.dp)
                    ) {
                        Icon(Icons.Default.Cloud, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Сгенерировать WARP (Cloudflare)")
                    }

                    FilledTonalButton(
                        onClick = onOpenSubscription,
                        modifier = Modifier.fillMaxWidth(),
                        contentPadding = PaddingValues(vertical = 10.dp)
                    ) {
                        Icon(Icons.Default.CloudDownload, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Подписка (URL)")
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = onPasteFromClipboard,
                            modifier = Modifier.weight(1f),
                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 10.dp)
                        ) {
                            Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Из буфера", fontSize = 12.sp, maxLines = 1)
                        }

                        OutlinedButton(
                            onClick = onImportFromFile,
                            modifier = Modifier.weight(1f),
                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 10.dp)
                        ) {
                            Icon(Icons.Default.FileOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Из файла", fontSize = 12.sp, maxLines = 1)
                        }
                    }

                    TextButton(
                        onClick = onOpenAddManual,
                        contentPadding = PaddingValues(vertical = 6.dp)
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Создать вручную", fontSize = 12.sp)
                    }
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 120.dp, top = 10.dp)
            ) {
                // 1. Standalone profiles (Список серверов)
                if (standaloneProfiles.isNotEmpty()) {
                    item(key = "group_standalone") {
                        val isExpanded = currentExpanded.contains("standalone")
                        ServerGroupCard(
                            title = "Список серверов",
                            subtitle = "${standaloneProfiles.size} ${declensionProfile(standaloneProfiles.size)}",
                            isExpanded = isExpanded,
                            onToggleExpand = {
                                expandedGroupKeys = if (isExpanded) {
                                    currentExpanded - "standalone"
                                } else {
                                    currentExpanded + "standalone"
                                }
                            },
                            onPing = { onPingProfiles(standaloneProfiles) },
                            isPinging = isTestingAll && standaloneProfiles.any { pingResults[it.id]?.isTesting == true }
                        ) {
                            standaloneProfiles.forEachIndexed { idx, profile ->
                                if (idx > 0) {
                                    HorizontalDivider(
                                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                                        thickness = 0.5.dp
                                    )
                                }
                                ProfileItemRow(
                                    profile = profile,
                                    isSelected = profile.id == selectedProfileId,
                                    showAddresses = showAddresses,
                                    fallbackStrategy = fallbackStrategy,
                                    pingResult = pingResults[profile.id],
                                    onSelect = { onSelectProfile(profile.id) },
                                    onEdit = { editingProfile = profile },
                                    onCopy = {
                                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                        val clip = android.content.ClipData.newPlainText("WireGuard Config", profile.rawConfig)
                                        cm.setPrimaryClip(clip)
                                        Toast.makeText(context, "Конфигурация скопирована", Toast.LENGTH_SHORT).show()
                                    },
                                    onDelete = { deletingProfileId = profile.id }
                                )
                            }
                        }
                    }
                }

                // 2. Subscriptions groups
                items(
                    items = effectiveSubscriptions,
                    key = { "group_sub_${it.url}" }
                ) { sub ->
                    val isExpanded = currentExpanded.contains(sub.url)
                    val subProfiles = remember(profiles, sub.url) {
                        profiles.filter { it.subscriptionUrl == sub.url }
                    }
                    val isUpdating = updatingSubscriptionUrls.contains(sub.url) ||
                        (isUpdatingSubscription && (subscriptions.firstOrNull()?.url == sub.url))

                    SubscriptionGroupCard(
                        subscription = sub,
                        profileCount = subProfiles.size,
                        isExpanded = isExpanded,
                        isUpdating = isUpdating,
                        isPinging = isTestingAll && subProfiles.any { pingResults[it.id]?.isTesting == true },
                        onToggleExpand = {
                            expandedGroupKeys = if (isExpanded) {
                                currentExpanded - sub.url
                            } else {
                                currentExpanded + sub.url
                            }
                        },
                        onRefresh = {
                            onUpdateSpecificSubscription(sub.url)
                        },
                        onPing = {
                            onPingProfiles(subProfiles)
                        },
                        onCopyUrl = {
                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = android.content.ClipData.newPlainText("Subscription URL", sub.url)
                            cm.setPrimaryClip(clip)
                            Toast.makeText(context, "URL подписки скопирован", Toast.LENGTH_SHORT).show()
                        },
                        onDeleteSubscription = {
                            deletingSubscription = sub
                        }
                    ) {
                        if (subProfiles.isEmpty()) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 14.dp, horizontal = 16.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = "В этой подписке пока нет конфигураций. Нажмите значок обновления.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        } else {
                            subProfiles.forEachIndexed { idx, profile ->
                                if (idx > 0) {
                                    HorizontalDivider(
                                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                                        thickness = 0.5.dp
                                    )
                                }
                                ProfileItemRow(
                                    profile = profile,
                                    isSelected = profile.id == selectedProfileId,
                                    showAddresses = showAddresses,
                                    fallbackStrategy = fallbackStrategy,
                                    pingResult = pingResults[profile.id],
                                    onSelect = { onSelectProfile(profile.id) },
                                    onEdit = { editingProfile = profile },
                                    onCopy = {
                                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                        val clip = android.content.ClipData.newPlainText("WireGuard Config", profile.rawConfig)
                                        cm.setPrimaryClip(clip)
                                        Toast.makeText(context, "Конфигурация скопирована", Toast.LENGTH_SHORT).show()
                                    },
                                    onDelete = { deletingProfileId = profile.id }
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    editingProfile?.let { prof ->
        AddEditProfileDialog(
            profile = prof,
            onDismiss = { editingProfile = null },
            onSave = {
                onAddOrUpdateProfile(it)
                editingProfile = null
            }
        )
    }

    deletingProfileId?.let { profId ->
        val prof = profiles.firstOrNull { it.id == profId }
        DeleteConfirmDialog(
            title = "Удалить профиль?",
            message = "Вы действительно хотите удалить конфигурацию «${prof?.name ?: ""}»?",
            onDismiss = { deletingProfileId = null },
            onConfirm = {
                onDeleteProfile(profId)
                deletingProfileId = null
            }
        )
    }

    deletingSubscription?.let { sub ->
        val subCount = profiles.count { it.subscriptionUrl == sub.url }
        DeleteConfirmDialog(
            title = "Удалить подписку?",
            message = "Вы действительно хотите удалить подписку «${sub.title}» и все её конфигурации ($subCount шт.)?",
            onDismiss = { deletingSubscription = null },
            onConfirm = {
                onDeleteSubscription(sub.url)
                deletingSubscription = null
            }
        )
    }
}

@Composable
private fun ServerGroupCard(
    title: String,
    subtitle: String,
    isExpanded: Boolean,
    onToggleExpand: () -> Unit,
    onPing: () -> Unit,
    isPinging: Boolean,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            // Header Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onToggleExpand)
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (isExpanded) Icons.Default.KeyboardArrowDown else Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = if (isExpanded) "Свернуть" else "Развернуть",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(24.dp)
                )

                Spacer(Modifier.width(8.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                    Text(
                        text = subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 12.sp
                    )
                }

                IconButton(
                    onClick = onPing,
                    enabled = !isPinging,
                    modifier = Modifier.size(36.dp)
                ) {
                    if (isPinging) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(
                            imageVector = Icons.Default.Speed,
                            contentDescription = "Тест скорости серверов",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }

            if (isExpanded) {
                HorizontalDivider(
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                    thickness = 0.8.dp
                )
                content()
            }
        }
    }
}

@Composable
private fun SubscriptionGroupCard(
    subscription: Subscription,
    profileCount: Int,
    isExpanded: Boolean,
    isUpdating: Boolean,
    isPinging: Boolean,
    onToggleExpand: () -> Unit,
    onRefresh: () -> Unit,
    onPing: () -> Unit,
    onCopyUrl: () -> Unit,
    onDeleteSubscription: () -> Unit,
    content: @Composable () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    val displayTitle = remember(subscription) {
        if (subscription.title.isNotBlank()) subscription.title else extractHost(subscription.url)
    }

    val displaySubtitle = remember(subscription, profileCount) {
        val lastUpdate = subscription.formattedLastUpdate()
        val autoInterval = if (subscription.updateIntervalHours != null) {
            " | Автообновление - ${subscription.updateIntervalHours} ч."
        } else ""
        "$lastUpdate$autoInterval"
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            // Header Row (like Happ)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onToggleExpand)
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (isExpanded) Icons.Default.KeyboardArrowDown else Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = if (isExpanded) "Свернуть" else "Развернуть",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(24.dp)
                )

                Spacer(Modifier.width(8.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = displayTitle,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = displaySubtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 11.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(
                        onClick = onRefresh,
                        enabled = !isUpdating,
                        modifier = Modifier.size(36.dp)
                    ) {
                        if (isUpdating) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                        } else {
                            Icon(
                                imageVector = Icons.Default.Sync,
                                contentDescription = "Обновить подписку",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }

                    IconButton(
                        onClick = onPing,
                        enabled = !isPinging && profileCount > 0,
                        modifier = Modifier.size(36.dp)
                    ) {
                        if (isPinging) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                        } else {
                            Icon(
                                imageVector = Icons.Default.Speed,
                                contentDescription = "Тест скорости",
                                tint = if (profileCount > 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }

                    Box {
                        IconButton(
                            onClick = { showMenu = true },
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.MoreVert,
                                contentDescription = "Действия с подпиской",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(20.dp)
                            )
                        }

                        DropdownMenu(
                            expanded = showMenu,
                            onDismissRequest = { showMenu = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text("Обновить подписку") },
                                onClick = {
                                    showMenu = false
                                    onRefresh()
                                },
                                leadingIcon = {
                                    Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                                }
                            )

                            DropdownMenuItem(
                                text = { Text("Скопировать URL") },
                                onClick = {
                                    showMenu = false
                                    onCopyUrl()
                                },
                                leadingIcon = {
                                    Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                                }
                            )

                            HorizontalDivider()

                            DropdownMenuItem(
                                text = {
                                    Text(
                                        "Удалить подписку",
                                        color = MaterialTheme.colorScheme.error,
                                        fontWeight = FontWeight.SemiBold
                                    )
                                },
                                onClick = {
                                    showMenu = false
                                    onDeleteSubscription()
                                },
                                leadingIcon = {
                                    Icon(
                                        Icons.Default.Delete,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.error,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            )
                        }
                    }
                }
            }

            // Traffic & Expiry info bar (Happ layout)
            val trafficText = subscription.formattedTraffic()
            val expireText = subscription.formattedExpire()
            if (trafficText != null || expireText != null) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                    border = BorderStroke(0.8.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Info,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )

                        Spacer(Modifier.width(8.dp))

                        if (trafficText != null) {
                            Text(
                                text = trafficText,
                                style = MaterialTheme.typography.bodySmall,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium
                            )
                        }

                        Spacer(Modifier.weight(1f))

                        if (expireText != null) {
                            Text(
                                text = expireText,
                                style = MaterialTheme.typography.bodySmall,
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                Spacer(Modifier.height(4.dp))
            }

            if (isExpanded) {
                HorizontalDivider(
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                    thickness = 0.8.dp
                )
                content()
            }
        }
    }
}

@Composable
private fun ProfileItemRow(
    profile: WgProfile,
    isSelected: Boolean,
    showAddresses: Boolean,
    fallbackStrategy: EvasionStrategy,
    pingResult: PingResult?,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onCopy: () -> Unit,
    onDelete: () -> Unit
) {
    var showItemMenu by remember { mutableStateOf(false) }

    val rowBgColor = if (isSelected) {
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f)
    } else {
        Color.Transparent
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onSelect)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Leading globe icon in a circular container (matches Happ design)
        Surface(
            shape = CircleShape,
            color = if (isSelected) {
                MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)
            } else {
                MaterialTheme.colorScheme.surfaceVariant
            },
            modifier = Modifier.size(38.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = Icons.Default.Public,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Spacer(Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = profile.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false)
                )

                if (isSelected) {
                    Badge(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary
                    ) {
                        Text(
                            "АКТИВЕН",
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 3.dp)
                        )
                    }
                }
            }

            Spacer(Modifier.height(2.dp))

            // Subtitle: protocol / endpoint / strategy
            val protoLabel = if (profile.rawConfig.contains("Jc =") || profile.rawConfig.contains("H1 =")) {
                "AmneziaWG"
            } else {
                "WireGuard"
            }

            val detailsText = buildString {
                append(protoLabel)
                if (showAddresses && profile.endpoint.isNotBlank()) {
                    append(" • ").append(profile.endpoint)
                }
                if (profile.hasEmbeddedStrategy) {
                    append(" • ⚡ ").append(profile.embeddedStrategy)
                }
            }

            Text(
                text = detailsText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        Spacer(Modifier.width(8.dp))

        // Ping Latency Result
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            if (pingResult?.isTesting == true) {
                CircularProgressIndicator(
                    modifier = Modifier.size(14.dp),
                    strokeWidth = 1.8.dp
                )
            } else if (pingResult != null) {
                val pingMs = pingResult.httpPingMs ?: pingResult.udpPingMs
                if (pingMs != null) {
                    Text(
                        text = "$pingMs мс",
                        color = Color(0xFF2E7D32),
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.sp
                    )
                } else if (pingResult.httpError || pingResult.udpError) {
                    Text(
                        text = "н/д",
                        color = MaterialTheme.colorScheme.error,
                        fontSize = 12.sp
                    )
                }
            }

            // Item actions menu
            Box {
                IconButton(
                    onClick = { showItemMenu = true },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.MoreVert,
                        contentDescription = "Действия",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                        modifier = Modifier.size(18.dp)
                    )
                }

                DropdownMenu(
                    expanded = showItemMenu,
                    onDismissRequest = { showItemMenu = false }
                ) {
                    DropdownMenuItem(
                        text = { Text("Выбрать конфигурацию") },
                        onClick = {
                            showItemMenu = false
                            onSelect()
                        },
                        leadingIcon = {
                            Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(18.dp))
                        }
                    )
                    DropdownMenuItem(
                        text = { Text("Редактировать") },
                        onClick = {
                            showItemMenu = false
                            onEdit()
                        },
                        leadingIcon = {
                            Icon(Icons.Default.Edit, contentDescription = null, modifier = Modifier.size(18.dp))
                        }
                    )
                    DropdownMenuItem(
                        text = { Text("Скопировать конфиг") },
                        onClick = {
                            showItemMenu = false
                            onCopy()
                        },
                        leadingIcon = {
                            Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(18.dp))
                        }
                    )
                    HorizontalDivider()
                    DropdownMenuItem(
                        text = {
                            Text(
                                "Удалить конфигурацию",
                                color = MaterialTheme.colorScheme.error
                            )
                        },
                        onClick = {
                            showItemMenu = false
                            onDelete()
                        },
                        leadingIcon = {
                            Icon(
                                Icons.Default.Delete,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    )
                }
            }
        }
    }
}

private fun extractHost(urlStr: String): String {
    return try {
        val uri = java.net.URI(urlStr)
        uri.host?.takeIf { it.isNotBlank() } ?: "Подписка"
    } catch (_: Exception) {
        "Подписка"
    }
}

private fun declensionProfile(count: Int): String {
    val mod10 = count % 10
    val mod100 = count % 100
    return when {
        mod100 in 11..19 -> "конфигураций"
        mod10 == 1 -> "конфигурация"
        mod10 in 2..4 -> "конфигурации"
        else -> "конфигураций"
    }
}
