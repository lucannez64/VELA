import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.vela.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.vela.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        compose = true
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("rustJniLibs"))

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.03.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.animation:animation")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.8")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("org.chromium.net:cronet-embedded:119.6045.31")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")

    debugImplementation("androidx.compose.ui:ui-tooling")
}

data class RustAndroidAbi(
    val androidAbi: String,
    val rustTarget: String,
    val clangPrefix: String,
    val ccEnv: String,
)

val rustAndroidAbis = listOf(
    RustAndroidAbi("arm64-v8a", "aarch64-linux-android", "aarch64-linux-android26", "CC_aarch64_linux_android"),
    RustAndroidAbi("armeabi-v7a", "armv7-linux-androideabi", "armv7a-linux-androideabi26", "CC_armv7_linux_androideabi"),
    RustAndroidAbi("x86", "i686-linux-android", "i686-linux-android26", "CC_i686_linux_android"),
    RustAndroidAbi("x86_64", "x86_64-linux-android", "x86_64-linux-android26", "CC_x86_64_linux_android"),
)

fun findAndroidSdkDir(): File {
    sequenceOf(
        System.getenv("ANDROID_SDK_ROOT"),
        System.getenv("ANDROID_HOME"),
        System.getenv("LOCALAPPDATA")?.let { "$it\\Android\\Sdk" },
        File(System.getProperty("user.home"), "AppData/Local/Android/Sdk").absolutePath,
    ).filterNotNull()
        .map(::File)
        .firstOrNull { it.isDirectory }
        ?.let { return it }

    error("Android SDK not found. Set ANDROID_SDK_ROOT or ANDROID_HOME.")
}

fun findAndroidNdkDir(sdkDir: File): File {
    sequenceOf(
        System.getenv("ANDROID_NDK_HOME"),
        System.getenv("ANDROID_NDK_ROOT"),
    ).filterNotNull()
        .map(::File)
        .firstOrNull { it.isDirectory }
        ?.let { return it }

    return sdkDir.resolve("ndk")
        .listFiles()
        ?.filter { it.isDirectory }
        ?.maxByOrNull { it.name }
        ?: error("Android NDK not found. Install it with sdkmanager or set ANDROID_NDK_HOME.")
}

fun rustTargetLinkerEnv(target: String): String =
    "CARGO_TARGET_${target.uppercase().replace("-", "_")}_LINKER"

tasks.register("buildRustBridge") {
    group = "build"
    description = "Builds libvela_android_bridge.so for Android ABIs."

    val outputRoot = layout.buildDirectory.dir("rustJniLibs")
    inputs.file(rootProject.projectDir.parentFile.resolve("libVELA/vela-android-bridge/Cargo.toml"))
    inputs.file(rootProject.projectDir.parentFile.resolve("libVELA/vela-android-bridge/Cargo.lock"))
    inputs.dir(rootProject.projectDir.parentFile.resolve("libVELA/vela-android-bridge/src"))
    inputs.file(rootProject.projectDir.parentFile.resolve("libVELA/vela-crypto/Cargo.toml"))
    inputs.dir(rootProject.projectDir.parentFile.resolve("libVELA/vela-crypto/src"))
    outputs.dir(outputRoot)

    doLast {
        val sdkDir = findAndroidSdkDir()
        val ndkDir = findAndroidNdkDir(sdkDir)
        val hostToolchain = ndkDir.resolve("toolchains/llvm/prebuilt")
            .listFiles()
            ?.firstOrNull { it.isDirectory && it.name.startsWith("windows-") }
            ?: error("NDK LLVM Windows toolchain not found in ${ndkDir.absolutePath}")
        val binDir = hostToolchain.resolve("bin")
        val ar = binDir.resolve("llvm-ar.exe")
        val bridgeDir = rootProject.projectDir.parentFile.resolve("libVELA/vela-android-bridge")

        rustAndroidAbis.forEach { abi ->
            val linker = binDir.resolve("${abi.clangPrefix}-clang.cmd")
            require(linker.isFile) { "Missing Android linker: ${linker.absolutePath}" }

            val cargo = ProcessBuilder("cargo", "build", "--release", "--target", abi.rustTarget)
                .directory(bridgeDir)
                .inheritIO()
            cargo.environment()["ANDROID_NDK_HOME"] = ndkDir.absolutePath
            cargo.environment()["CARGO_BUILD_JOBS"] = "1"
            cargo.environment()[rustTargetLinkerEnv(abi.rustTarget)] = linker.absolutePath
            cargo.environment()[abi.ccEnv] = linker.absolutePath
            cargo.environment()["AR_${abi.rustTarget.replace("-", "_")}"] = ar.absolutePath
            val exitCode = cargo.start().waitFor()
            require(exitCode == 0) { "cargo build failed for ${abi.rustTarget} with exit code $exitCode" }

            val source = bridgeDir.resolve("target/${abi.rustTarget}/release/libvela_android_bridge.so")
            require(source.isFile) { "Cargo did not produce ${source.absolutePath}" }

            project.copy {
                from(source)
                into(outputRoot.get().asFile.resolve(abi.androidAbi))
                rename { "libvela_android_bridge.so" }
            }
        }
    }
}

tasks.matching { it.name == "preBuild" || (it.name.startsWith("merge") && it.name.endsWith("JniLibFolders")) }
    .configureEach {
        dependsOn("buildRustBridge")
    }
