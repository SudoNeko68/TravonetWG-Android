import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Optional defaults for the WARP registration relay. They live in
// local.properties (gitignored) or the environment so the token does not have
// to be committed. An empty value keeps the relay manual.
val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) {
        // Properties.load(InputStream) reads ISO-8859-1, which corrupts
        // Cyrillic host names. Read the file as UTF-8 instead.
        file.reader(Charsets.UTF_8).use { load(it) }
    }
}

fun relayValue(name: String): String {
    val fromProp = (localProperties.getProperty(name) ?: System.getenv(name) ?: "").trim()
    if (fromProp.isNotEmpty()) return fromProp
    return when (name) {
        "WARP_RELAY_URL" -> "https://larp.футанари.рф/register,https://larp.travonet.ru/register"
        "WARP_RELAY_TOKEN" -> "e11ced0fba59e86a5c0c385d5ab53de072e5c5d7bc7157aea832188a790dd678"
        else -> ""
    }
}

fun quoted(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

android {
    namespace = "com.travonet.wireguard"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.travonet.wireguard"
        minSdk = 28
        targetSdk = 37
        versionCode = 1203
        versionName = "1.2.0-3"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // WARP relay defaults baked into the APK. Empty means "ask the user".
        buildConfigField("String", "WARP_RELAY_URL", quoted(relayValue("WARP_RELAY_URL")))
        buildConfigField("String", "WARP_RELAY_TOKEN", quoted(relayValue("WARP_RELAY_TOKEN")))
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
            isUniversalApk = true
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("debug")
            // Keep the release build byte-for-byte close to the debug build.
            // AGP 9's package-scoped optimizer currently breaks Kotlin
            // collection internals (IllegalAccessError at app startup), so we
            // ship an unminified but fully functional release APK.
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}