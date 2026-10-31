plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
val ciDebugKeystorePath = System.getenv("PROXYGUARD_DEBUG_KEYSTORE")

android {
    signingConfigs {
        if (!ciDebugKeystorePath.isNullOrBlank()) {
            create("ciDebug") {
                storeFile = file(ciDebugKeystorePath)
                storePassword = "android"
                keyAlias = "proxyguard-debug"
                keyPassword = "android"
            }
        }
    }
    buildTypes {
        getByName("debug") {
            if (!ciDebugKeystorePath.isNullOrBlank()) {
                signingConfig = signingConfigs.getByName("ciDebug")
            }
        }
    }
    namespace = "com.proxyguard.android"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.proxyguard.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 15
        versionName = "0.6.5"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}


dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260719")
}
