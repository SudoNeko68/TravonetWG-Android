package com.travonet.wireguard.core

import android.content.Context
import android.os.Build
import android.util.Log
import com.travonet.wireguard.repository.AppRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.travonet.backend.GoBackend
import java.io.File

class CoreManager(private val context: Context) {

    private val repository = AppRepository(context)

    private val coresDir: File by lazy {
        File(context.filesDir, "cores").apply { if (!exists()) mkdirs() }
    }

    private val _cores = MutableStateFlow<List<CoreInfo>>(emptyList())
    val cores: StateFlow<List<CoreInfo>> = _cores.asStateFlow()

    private val _activeInstallingCore = MutableStateFlow<CoreType?>(null)
    val activeInstallingCore: StateFlow<CoreType?> = _activeInstallingCore.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    private var remoteManifest: RemoteManifest? = null

    init {
        // Load custom rolling TravonetWG core if selected
        val customTravonet = getCoreFilePath(context, CoreType.TRAVONET_WG)
        if (customTravonet != null) {
            GoBackend.loadCustomCore(customTravonet)
        }

        refreshCores()
        // Asynchronously fetch manifest from remote repository
        CoroutineScope(Dispatchers.IO).launch {
            fetchRemoteManifest()
        }
    }

    suspend fun fetchRemoteManifest() {
        val result = CoreRepositoryClient.fetchManifest(context, REPO_BASE_URL)
        if (result.isSuccess) {
            remoteManifest = result.getOrNull()
            refreshCores()
        }
    }

    fun refreshCores() {
        val manifest = remoteManifest ?: CoreRepositoryClient.getBuiltinManifest(REPO_BASE_URL)

        val travonetVer = repository.getSelectedCoreVersion(CoreType.TRAVONET_WG.id) ?: BUILTIN_TRAVONET_VERSION
        val xrayVer = repository.getSelectedCoreVersion(CoreType.XRAY.id) ?: BUILTIN_XRAY_VERSION
        val singboxVer = repository.getSelectedCoreVersion(CoreType.SINGBOX.id) ?: BUILTIN_SINGBOX_VERSION
        val freeturnVer = repository.getSelectedCoreVersion(CoreType.FREETURN.id) ?: BUILTIN_FREETURN_VERSION

        val travonetEntry = manifest.cores.find { it.id == CoreType.TRAVONET_WG.id }
        val xrayEntry = manifest.cores.find { it.id == CoreType.XRAY.id }
        val singboxEntry = manifest.cores.find { it.id == CoreType.SINGBOX.id }
        val freeturnEntry = manifest.cores.find { it.id == CoreType.FREETURN.id }

        val travonetAvailVersions = (travonetEntry?.versions?.map { it.version } ?: listOf(BUILTIN_TRAVONET_VERSION, "1.2.0"))
            .distinct()
        val xrayAvailVersions = (xrayEntry?.versions?.map { it.version } ?: listOf(BUILTIN_XRAY_VERSION, "1.8.23"))
            .distinct()
        val singboxAvailVersions = (singboxEntry?.versions?.map { it.version } ?: listOf(BUILTIN_SINGBOX_VERSION, "1.9.0"))
            .distinct()
        val freeturnAvailVersions = (freeturnEntry?.versions?.map { it.version } ?: listOf(BUILTIN_FREETURN_VERSION))
            .distinct()

        val travonetFile = getVersionedCoreFile(context, CoreType.TRAVONET_WG, travonetVer)
        val xrayFile = getVersionedCoreFile(context, CoreType.XRAY, xrayVer)
        val singboxFile = getVersionedCoreFile(context, CoreType.SINGBOX, singboxVer)
        val freeturnFile = getVersionedCoreFile(context, CoreType.FREETURN, freeturnVer)

        val hasNativeTravonet = isNativeLibPresent(context, CoreType.TRAVONET_WG.binaryName)
        val hasNativeXray = isNativeLibPresent(context, CoreType.XRAY.binaryName)
        val hasNativeSingbox = isNativeLibPresent(context, CoreType.SINGBOX.binaryName)
        val hasNativeFreeturn = isNativeLibPresent(context, CoreType.FREETURN.binaryName)

        val travonetStatus = evaluateStatus(travonetVer, BUILTIN_TRAVONET_VERSION, travonetFile, hasNativeTravonet)
        val xrayStatus = evaluateStatus(xrayVer, BUILTIN_XRAY_VERSION, xrayFile, hasNativeXray)
        val singboxStatus = evaluateStatus(singboxVer, BUILTIN_SINGBOX_VERSION, singboxFile, hasNativeSingbox)
        val freeturnStatus = evaluateStatus(freeturnVer, BUILTIN_FREETURN_VERSION, freeturnFile, hasNativeFreeturn)

        val list = listOf(
            CoreInfo(
                type = CoreType.TRAVONET_WG,
                version = BUILTIN_TRAVONET_VERSION,
                selectedVersion = travonetVer,
                availableVersions = travonetAvailVersions,
                status = travonetStatus,
                sizeBytes = if (travonetFile.exists()) travonetFile.length() else 9L * 1024 * 1024,
                supportedProtocols = listOf("WireGuard", "AmneziaWG", "WARP"),
                filePath = getCoreFilePath(context, CoreType.TRAVONET_WG)
            ),
            CoreInfo(
                type = CoreType.XRAY,
                version = BUILTIN_XRAY_VERSION,
                selectedVersion = xrayVer,
                availableVersions = xrayAvailVersions,
                status = xrayStatus,
                sizeBytes = if (xrayFile.exists()) xrayFile.length() else 37L * 1024 * 1024,
                supportedProtocols = listOf("VLESS (Reality/Vision)", "VMess", "Trojan", "Shadowsocks"),
                filePath = getCoreFilePath(context, CoreType.XRAY)
            ),
            CoreInfo(
                type = CoreType.SINGBOX,
                version = BUILTIN_SINGBOX_VERSION,
                selectedVersion = singboxVer,
                availableVersions = singboxAvailVersions,
                status = singboxStatus,
                sizeBytes = if (singboxFile.exists()) singboxFile.length() else 46L * 1024 * 1024,
                supportedProtocols = listOf("TUIC v5", "Hysteria 2", "ShadowTLS"),
                filePath = getCoreFilePath(context, CoreType.SINGBOX)
            ),
            CoreInfo(
                type = CoreType.FREETURN,
                version = BUILTIN_FREETURN_VERSION,
                selectedVersion = freeturnVer,
                availableVersions = freeturnAvailVersions,
                status = freeturnStatus,
                sizeBytes = if (freeturnFile.exists()) freeturnFile.length() else 18L * 1024 * 1024,
                supportedProtocols = listOf("FreeTURN (VK Calls TURN Relay)"),
                filePath = getCoreFilePath(context, CoreType.FREETURN)
            )
        )
        _cores.value = list
    }

    private fun evaluateStatus(
        selectedVer: String,
        builtinVer: String,
        versionedFile: File,
        hasNativeLib: Boolean
    ): CoreStatus {
        return when {
            selectedVer == builtinVer && hasNativeLib -> CoreStatus.BUILTIN
            versionedFile.exists() && versionedFile.length() >= 1024 * 1024 -> CoreStatus.INSTALLED
            selectedVer == builtinVer -> CoreStatus.BUILTIN
            else -> CoreStatus.NOT_INSTALLED
        }
    }

    fun selectVersion(coreType: CoreType, version: String) {
        repository.setSelectedCoreVersion(coreType.id, version)
        if (coreType == CoreType.TRAVONET_WG) {
            val custom = getCoreFilePath(context, coreType)
            GoBackend.loadCustomCore(custom)
        }
        refreshCores()
    }

    suspend fun installOrUpdateCore(coreType: CoreType, version: String): Result<String> = withContext(Dispatchers.IO) {
        _activeInstallingCore.value = coreType
        _statusMessage.value = "Загрузка ${coreType.title} v$version из репозитория..."

        val binaryName = coreType.binaryName
        val targetFile = getVersionedCoreFile(context, coreType, version)
        targetFile.parentFile?.mkdirs()

        // 1. Check if remote manifest has this version and ABI
        val manifest = remoteManifest ?: CoreRepositoryClient.fetchManifest(context, REPO_BASE_URL).getOrNull()
        val coreEntry = manifest?.cores?.find { it.id == coreType.id }
        val verEntry = coreEntry?.versions?.find { it.version == version }
        val abiMatch = verEntry?.getAbi(Build.SUPPORTED_ABIS)

        if (abiMatch != null) {
            val (matchedAbi, abiData) = abiMatch
            Log.i("CoreManager", "Downloading ${coreType.id} v$version ($matchedAbi) from ${abiData.url}")
            val downloadResult = CoreRepositoryClient.downloadCore(
                url = abiData.url,
                targetFile = targetFile,
                expectedSha256 = abiData.sha256.takeIf { it.isNotEmpty() }
            )

            if (downloadResult.isSuccess) {
                targetFile.setExecutable(true)
                selectVersion(coreType, version)
                if (coreType == CoreType.TRAVONET_WG) {
                    GoBackend.loadCustomCore(targetFile.absolutePath)
                }
                val msg = "Ядро ${coreType.title} v$version успешно скачано и активировано."
                _statusMessage.value = msg
                _activeInstallingCore.value = null
                refreshCores()
                return@withContext Result.success(msg)
            } else {
                Log.w("CoreManager", "Remote download failed: ${downloadResult.exceptionOrNull()?.message}")
            }
        }

        // 2. Fallback: if remote repo is unreachable but user selected builtin version, use packaged library
        val builtinVer = when (coreType) {
            CoreType.TRAVONET_WG -> BUILTIN_TRAVONET_VERSION
            CoreType.XRAY -> BUILTIN_XRAY_VERSION
            CoreType.SINGBOX -> BUILTIN_SINGBOX_VERSION
            CoreType.FREETURN -> BUILTIN_FREETURN_VERSION
        }

        if (version == builtinVer) {
            val builtinFile = File(context.applicationInfo.nativeLibraryDir, binaryName)
            if (builtinFile.exists() && builtinFile.length() > 0) {
                builtinFile.copyTo(targetFile, overwrite = true)
            } else {
                extractFromApkIfNeeded(context, binaryName)?.let { extracted ->
                    extracted.copyTo(targetFile, overwrite = true)
                }
            }
            targetFile.setExecutable(true)
            selectVersion(coreType, version)
            if (coreType == CoreType.TRAVONET_WG) {
                GoBackend.loadCustomCore(targetFile.absolutePath)
            }
            val msg = "Ядро ${coreType.title} v$version активировано (встроенная версия)."
            _statusMessage.value = msg
            _activeInstallingCore.value = null
            refreshCores()
            return@withContext Result.success(msg)
        }

        _activeInstallingCore.value = null
        refreshCores()
        val errMsg = "Не удалось скачать ядро ${coreType.title} v$version с $REPO_BASE_URL. Проверьте соединение с репозиторием."
        _statusMessage.value = errMsg
        Result.failure(Exception(errMsg))
    }

    fun isInstalled(type: CoreType): Boolean = Companion.isInstalled(context, type)

    companion object {
        const val REPO_BASE_URL = "https://repo.travonet.ru/cores"
        const val BUILTIN_TRAVONET_VERSION = "1.3.1"
        const val BUILTIN_XRAY_VERSION = "1.8.24"
        const val BUILTIN_SINGBOX_VERSION = "1.10.7"
        const val BUILTIN_FREETURN_VERSION = "1.0.0"

        fun isInstalled(context: Context, type: CoreType): Boolean {
            return getCoreFilePath(context, type) != null
        }

        fun getVersionedCoreFile(context: Context, type: CoreType, version: String): File {
            val dir = File(context.filesDir, "cores/${type.id}/$version")
            return File(dir, type.binaryName)
        }

        fun getCoreFilePath(context: Context, type: CoreType): String? {
            val binaryName = type.binaryName
            val repo = AppRepository(context)
            val selectedVer = repo.getSelectedCoreVersion(type.id)

            // 1. Check versioned downloaded file
            if (!selectedVer.isNullOrBlank()) {
                val versionedFile = getVersionedCoreFile(context, type, selectedVer)
                if (versionedFile.exists() && versionedFile.length() >= 1024 * 1024) {
                    return versionedFile.absolutePath
                }
            }

            // 2. Check legacy unversioned downloaded core
            val legacyCustom = File(File(context.filesDir, "cores"), binaryName)
            if (legacyCustom.exists() && legacyCustom.length() >= 1024 * 1024) {
                return legacyCustom.absolutePath
            }

            // 3. Check builtin package library from nativeLibraryDir
            val builtin = File(context.applicationInfo.nativeLibraryDir, binaryName)
            if (builtin.exists() && builtin.length() > 1024) {
                return builtin.absolutePath
            }

            // 4. Auto-extract from APK if needed
            val extracted = extractFromApkIfNeeded(context, binaryName)
            if (extracted != null && extracted.exists() && extracted.length() >= 1024 * 1024) {
                return extracted.absolutePath
            }

            return null
        }

        fun extractFromApkIfNeeded(context: Context, binaryName: String): File? {
            val coresDir = File(context.filesDir, "cores").apply { if (!exists()) mkdirs() }
            val targetFile = File(coresDir, binaryName)
            if (targetFile.exists() && targetFile.length() >= 1024 * 1024) {
                return targetFile
            }

            return try {
                val apkPath = context.applicationInfo.sourceDir
                java.util.zip.ZipFile(apkPath).use { zip ->
                    val supportedAbis = android.os.Build.SUPPORTED_ABIS
                    var matchedEntry: java.util.zip.ZipEntry? = null
                    for (abi in supportedAbis) {
                        val entry = zip.getEntry("lib/$abi/$binaryName")
                        if (entry != null) {
                            matchedEntry = entry
                            break
                        }
                    }
                    if (matchedEntry == null) return null

                    val tempFile = File(coresDir, "$binaryName.tmp")
                    zip.getInputStream(matchedEntry).use { input ->
                        tempFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                    if (tempFile.renameTo(targetFile) || (targetFile.delete() && tempFile.renameTo(targetFile))) {
                        targetFile.setExecutable(true)
                        targetFile
                    } else {
                        null
                    }
                }
            } catch (_: Exception) {
                null
            }
        }

        private fun isNativeLibPresent(context: Context, libName: String): Boolean {
            val f = File(context.applicationInfo.nativeLibraryDir, libName)
            if (f.exists() && f.length() > 1024) return true

            return try {
                java.util.zip.ZipFile(context.applicationInfo.sourceDir).use { zip ->
                    android.os.Build.SUPPORTED_ABIS.any { abi ->
                        zip.getEntry("lib/$abi/$libName") != null
                    }
                }
            } catch (_: Exception) {
                false
            }
        }
    }
}
