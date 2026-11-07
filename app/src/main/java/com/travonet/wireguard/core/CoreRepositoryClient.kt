package com.travonet.wireguard.core

import android.content.Context
import android.os.Build
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

data class RemoteCoreAbi(
    val url: String,
    val sha256: String = "",
    val sizeBytes: Long = 0
)

data class RemoteCoreVersion(
    val version: String,
    val date: String = "",
    val abis: Map<String, RemoteCoreAbi> = emptyMap()
) {
    fun getAbi(preferredAbis: Array<String> = Build.SUPPORTED_ABIS): Pair<String, RemoteCoreAbi>? {
        for (abi in preferredAbis) {
            val entry = abis[abi]
            if (entry != null) return Pair(abi, entry)
        }
        return abis.entries.firstOrNull()?.let { Pair(it.key, it.value) }
    }
}

data class RemoteCoreEntry(
    val id: String,
    val name: String,
    val binaryName: String,
    val latestVersion: String = "",
    val versions: List<RemoteCoreVersion> = emptyList()
)

data class RemoteManifest(
    val manifestVersion: Int = 1,
    val cores: List<RemoteCoreEntry> = emptyList()
)

object CoreRepositoryClient {
    private const val TAG = "CoreRepositoryClient"
    const val DEFAULT_REPO_URL = "https://repo.travonet.ru/cores"
    private const val MANIFEST_FILE = "cores_manifest.json"

    suspend fun fetchManifest(
        context: Context,
        repoBaseUrl: String = DEFAULT_REPO_URL
    ): Result<RemoteManifest> = withContext(Dispatchers.IO) {
        val manifestUrl = "${repoBaseUrl.trimEnd('/')}/manifest.json"
        try {
            val url = URL(manifestUrl)
            val conn = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 6000
                readTimeout = 10000
                setRequestProperty("User-Agent", "TravonetVPN-CoreLoader/2.0")
                setRequestProperty("Accept", "application/json")
            }

            if (conn.responseCode == 200) {
                val jsonString = conn.inputStream.bufferedReader().use { it.readText() }
                // Cache manifest locally
                try {
                    val cacheFile = File(context.filesDir, MANIFEST_FILE)
                    cacheFile.writeText(jsonString)
                } catch (_: Exception) {}

                val manifest = parseManifestJson(jsonString, repoBaseUrl)
                return@withContext Result.success(manifest)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to fetch remote manifest from $manifestUrl: ${e.message}")
        }

        // Fallback: try cached manifest
        try {
            val cacheFile = File(context.filesDir, MANIFEST_FILE)
            if (cacheFile.exists() && cacheFile.length() > 0) {
                val cachedJson = cacheFile.readText()
                val manifest = parseManifestJson(cachedJson, repoBaseUrl)
                return@withContext Result.success(manifest)
            }
        } catch (_: Exception) {}

        // Fallback: builtin default manifest
        Result.success(getBuiltinManifest(repoBaseUrl))
    }

    suspend fun downloadCore(
        url: String,
        targetFile: File,
        expectedSha256: String? = null,
        onProgress: (Float) -> Unit = {}
    ): Result<File> = withContext(Dispatchers.IO) {
        val tempFile = File(targetFile.parentFile ?: targetFile, "${targetFile.name}.downloading")
        try {
            val downloadUrl = URL(url)
            val conn = (downloadUrl.openConnection() as HttpURLConnection).apply {
                connectTimeout = 10000
                readTimeout = 30000
                setRequestProperty("User-Agent", "TravonetVPN-CoreLoader/2.0")
            }

            if (conn.responseCode !in 200..299) {
                return@withContext Result.failure(Exception("HTTP error ${conn.responseCode}"))
            }

            val totalBytes: Long = conn.contentLengthLong.takeIf { it > 0 } ?: -1L
            var downloadedBytes = 0L

            conn.inputStream.use { input ->
                tempFile.outputStream().use { output ->
                    val buffer = ByteArray(16384)
                    var read: Int
                    while (input.read(buffer).also { read = it } != -1) {
                        output.write(buffer, 0, read)
                        downloadedBytes += read
                        if (totalBytes > 0L) {
                            onProgress(downloadedBytes.toFloat() / totalBytes.toFloat())
                        }
                    }
                }
            }

            // Verify SHA256 if provided
            if (!expectedSha256.isNullOrBlank()) {
                val actualSha256 = calculateSha256(tempFile)
                if (!actualSha256.equals(expectedSha256.trim(), ignoreCase = true)) {
                    tempFile.delete()
                    return@withContext Result.failure(
                        Exception("SHA256 mismatch: expected $expectedSha256, got $actualSha256")
                    )
                }
            }

            if (targetFile.exists()) {
                targetFile.delete()
            }
            if (tempFile.renameTo(targetFile) || (targetFile.delete() && tempFile.renameTo(targetFile))) {
                targetFile.setExecutable(true)
                return@withContext Result.success(targetFile)
            } else {
                return@withContext Result.failure(Exception("Failed to move temp file to ${targetFile.name}"))
            }
        } catch (e: Exception) {
            try { tempFile.delete() } catch (_: Exception) {}
            Result.failure(e)
        }
    }

    fun calculateSha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun parseManifestJson(jsonStr: String, repoBaseUrl: String): RemoteManifest {
        val root = JSONObject(jsonStr)
        val manifestVersion = root.optInt("manifest_version", root.optInt("version", 1))
        val coresArray = root.optJSONArray("cores") ?: return RemoteManifest(manifestVersion, emptyList())

        val coresList = mutableListOf<RemoteCoreEntry>()
        for (i in 0 until coresArray.length()) {
            val coreObj = coresArray.optJSONObject(i) ?: continue
            val id = coreObj.optString("id", "")
            if (id.isEmpty()) continue
            val name = coreObj.optString("name", id)
            val binaryName = coreObj.optString("binary_name", "lib$id.so")
            val latestVersion = coreObj.optString("latest_version", "")

            val versionsArray = coreObj.optJSONArray("versions")
            val versionsList = mutableListOf<RemoteCoreVersion>()
            if (versionsArray != null) {
                for (j in 0 until versionsArray.length()) {
                    val verObj = versionsArray.optJSONObject(j) ?: continue
                    val verStr = verObj.optString("version", "")
                    if (verStr.isEmpty()) continue
                    val date = verObj.optString("date", "")

                    val abisObj = verObj.optJSONObject("abis")
                    val abisMap = mutableMapOf<String, RemoteCoreAbi>()
                    if (abisObj != null) {
                        for (abiKey in abisObj.keys()) {
                            val abiData = abisObj.optJSONObject(abiKey) ?: continue
                            var url = abiData.optString("url", "")
                            if (url.isNotEmpty() && !url.startsWith("http://") && !url.startsWith("https://")) {
                                url = "${repoBaseUrl.trimEnd('/')}/$url"
                            }
                            val sha = abiData.optString("sha256", "")
                            val size = abiData.optLong("size", abiData.optLong("size_bytes", 0L))
                            abisMap[abiKey] = RemoteCoreAbi(url = url, sha256 = sha, sizeBytes = size)
                        }
                    }
                    versionsList.add(RemoteCoreVersion(version = verStr, date = date, abis = abisMap))
                }
            }
            coresList.add(
                RemoteCoreEntry(
                    id = id,
                    name = name,
                    binaryName = binaryName,
                    latestVersion = latestVersion,
                    versions = versionsList
                )
            )
        }
        return RemoteManifest(manifestVersion, coresList)
    }

    fun getBuiltinManifest(repoBaseUrl: String = DEFAULT_REPO_URL): RemoteManifest {
        val base = repoBaseUrl.trimEnd('/')
        return RemoteManifest(
            manifestVersion = 1,
            cores = listOf(
                RemoteCoreEntry(
                    id = "travonet_wg",
                    name = "TravonetWG",
                    binaryName = "libtravonet-wg.so",
                    latestVersion = "1.3.1",
                    versions = listOf(
                        RemoteCoreVersion(
                            version = "1.3.1",
                            date = "2026-11-07",
                            abis = mapOf(
                                "arm64-v8a" to RemoteCoreAbi("$base/travonet_wg/1.3.1/arm64-v8a/libtravonet-wg.so"),
                                "armeabi-v7a" to RemoteCoreAbi("$base/travonet_wg/1.3.1/armeabi-v7a/libtravonet-wg.so"),
                                "x86_64" to RemoteCoreAbi("$base/travonet_wg/1.3.1/x86_64/libtravonet-wg.so"),
                                "x86" to RemoteCoreAbi("$base/travonet_wg/1.3.1/x86/libtravonet-wg.so")
                            )
                        ),
                        RemoteCoreVersion(
                            version = "1.3",
                            date = "2026-11-07",
                            abis = mapOf(
                                "arm64-v8a" to RemoteCoreAbi("$base/travonet_wg/1.3/arm64-v8a/libtravonet-wg.so"),
                                "armeabi-v7a" to RemoteCoreAbi("$base/travonet_wg/1.3/armeabi-v7a/libtravonet-wg.so"),
                                "x86_64" to RemoteCoreAbi("$base/travonet_wg/1.3/x86_64/libtravonet-wg.so"),
                                "x86" to RemoteCoreAbi("$base/travonet_wg/1.3/x86/libtravonet-wg.so")
                            )
                        ),
                        RemoteCoreVersion(
                            version = "1.2.0",
                            date = "2024-11-04",
                            abis = mapOf(
                                "arm64-v8a" to RemoteCoreAbi("$base/travonet_wg/1.2.0/arm64-v8a/libtravonet-wg.so"),
                                "armeabi-v7a" to RemoteCoreAbi("$base/travonet_wg/1.2.0/armeabi-v7a/libtravonet-wg.so"),
                                "x86_64" to RemoteCoreAbi("$base/travonet_wg/1.2.0/x86_64/libtravonet-wg.so"),
                                "x86" to RemoteCoreAbi("$base/travonet_wg/1.2.0/x86/libtravonet-wg.so")
                            )
                        )
                    )
                ),
                RemoteCoreEntry(
                    id = "xray",
                    name = "Xray-Core",
                    binaryName = "libxray.so",
                    latestVersion = "1.8.24",
                    versions = listOf(
                        RemoteCoreVersion(
                            version = "1.8.24",
                            date = "2024-10-15",
                            abis = mapOf(
                                "arm64-v8a" to RemoteCoreAbi("$base/xray/1.8.24/arm64-v8a/libxray.so"),
                                "armeabi-v7a" to RemoteCoreAbi("$base/xray/1.8.24/armeabi-v7a/libxray.so"),
                                "x86_64" to RemoteCoreAbi("$base/xray/1.8.24/x86_64/libxray.so")
                            )
                        ),
                        RemoteCoreVersion(
                            version = "1.8.23",
                            date = "2024-09-01",
                            abis = mapOf(
                                "arm64-v8a" to RemoteCoreAbi("$base/xray/1.8.23/arm64-v8a/libxray.so"),
                                "armeabi-v7a" to RemoteCoreAbi("$base/xray/1.8.23/armeabi-v7a/libxray.so"),
                                "x86_64" to RemoteCoreAbi("$base/xray/1.8.23/x86_64/libxray.so")
                            )
                        )
                    )
                ),
                RemoteCoreEntry(
                    id = "singbox",
                    name = "Sing-Box",
                    binaryName = "libsingbox.so",
                    latestVersion = "1.10.7",
                    versions = listOf(
                        RemoteCoreVersion(
                            version = "1.10.7",
                            date = "2024-10-20",
                            abis = mapOf(
                                "arm64-v8a" to RemoteCoreAbi("$base/singbox/1.10.7/arm64-v8a/libsingbox.so"),
                                "armeabi-v7a" to RemoteCoreAbi("$base/singbox/1.10.7/armeabi-v7a/libsingbox.so"),
                                "x86_64" to RemoteCoreAbi("$base/singbox/1.10.7/x86_64/libsingbox.so")
                            )
                        ),
                        RemoteCoreVersion(
                            version = "1.9.0",
                            date = "2024-06-10",
                            abis = mapOf(
                                "arm64-v8a" to RemoteCoreAbi("$base/singbox/1.9.0/arm64-v8a/libsingbox.so"),
                                "armeabi-v7a" to RemoteCoreAbi("$base/singbox/1.9.0/armeabi-v7a/libsingbox.so"),
                                "x86_64" to RemoteCoreAbi("$base/singbox/1.9.0/x86_64/libsingbox.so")
                            )
                        )
                    )
                ),
                RemoteCoreEntry(
                    id = "freeturn",
                    name = "FreeTURN",
                    binaryName = "libfreeturn.so",
                    latestVersion = "1.0.0",
                    versions = listOf(
                        RemoteCoreVersion(
                            version = "1.0.0",
                            date = "2024-11-01",
                            abis = mapOf(
                                "arm64-v8a" to RemoteCoreAbi("$base/freeturn/1.0.0/arm64-v8a/libfreeturn.so"),
                                "armeabi-v7a" to RemoteCoreAbi("$base/freeturn/1.0.0/armeabi-v7a/libfreeturn.so"),
                                "x86_64" to RemoteCoreAbi("$base/freeturn/1.0.0/x86_64/libfreeturn.so")
                            )
                        )
                    )
                )
            )
        )
    }
}
