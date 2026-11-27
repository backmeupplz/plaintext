import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The release key lives outside git (Vaultwarden "Plaintext: Android release keystore"): android/keystore.properties
// and the .jks it names. Without it, release builds come out unsigned (CI).
val keys = Properties().apply { rootProject.file("keystore.properties").takeIf { it.exists() }?.inputStream()?.use { load(it) } }

android {
    namespace = "com.borodutch.plaintext"
    compileSdk = 37
    defaultConfig {
        applicationId = "com.borodutch.plaintext"
        minSdk = 29
        targetSdk = 36
        // Minutes since the epoch, so every build installs over the last one without a bump.
        versionCode = (System.currentTimeMillis() / 60_000).toInt()
        versionName = providers.gradleProperty("versionName").getOrElse("0.1.0")
    }
    signingConfigs {
        if (keys.isNotEmpty()) create("release") {
            storeFile = rootProject.file(keys.getProperty("storeFile"))
            storePassword = keys.getProperty("storePassword")
            keyAlias = keys.getProperty("keyAlias")
            keyPassword = keys.getProperty("keyPassword")
        }
    }
    buildFeatures { compose = true; buildConfig = true }
    dependenciesInfo { includeInApk = false }
    // build.sh puts the Rust libraries and their Kotlin bindings here.
    sourceSets["main"].kotlin.srcDir("build/generated/uniffi")
    sourceSets["main"].jniLibs.srcDir("build/generated/jniLibs")
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
        debug { applicationIdSuffix = ".debug" }
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended") // R8 strips the unused ones
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment:1.8.9") // biometric pulls an old one that breaks activity results
    implementation("androidx.camera:camera-camera2:1.5.1")
    implementation("androidx.camera:camera-lifecycle:1.5.1")
    implementation("androidx.camera:camera-view:1.5.1")
    implementation("com.google.zxing:core:3.5.4") // QR codes: draw and decode, no Play Services
    implementation("net.java.dev.jna:jna:5.18.1@aar") // what UniFFI's Kotlin bindings call Rust through
}
