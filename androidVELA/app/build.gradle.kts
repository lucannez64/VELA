import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing inputs, read before `android {}` so the task-graph guard at
// the bottom of this file can see them too.
val releaseKeystorePath = (project.findProperty("velaKeystoreFile") as String?)
    ?: System.getenv("VELA_KEYSTORE_FILE")
val hasReleaseKeystore =
    !releaseKeystorePath.isNullOrBlank() && File(releaseKeystorePath).exists()
val allowDebugSigning = ((project.findProperty("velaAllowDebugSigning") as String?)
    ?: System.getenv("VELA_ALLOW_DEBUG_SIGNING"))?.toBoolean() ?: false

android {
    namespace = "com.vela.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.vela.android"
        minSdk = 26
        targetSdk = 35
        // Overridable from CI: -PvelaVersionCode=<int> -PvelaVersionName=<str>.
        versionCode = (project.findProperty("velaVersionCode") as String?)?.toIntOrNull() ?: 1
        versionName = (project.findProperty("velaVersionName") as String?) ?: "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        compose = true
    }

    // Stable release signing: when a keystore is supplied (CI secrets, via
    // -Pvela* properties or VELA_* env vars) sign with it so every build is
    // mutually upgradeable.
    //
    // There used to be a silent fallback to the per-machine debug key, so a
    // "release" APK could ship signed with a well-known key — installable over
    // nothing and trivially impersonated by a rebuilt APK (audit A-3). A release
    // build without a keystore now fails; a developer who wants a locally
    // signed one opts in explicitly with -PvelaAllowDebugSigning=true.
    signingConfigs {
        if (hasReleaseKeystore) {
            create("release") {
                storeFile = File(releaseKeystorePath)
                storePassword = (project.findProperty("velaKeystorePassword") as String?)
                    ?: System.getenv("VELA_KEYSTORE_PASSWORD")
                keyAlias = (project.findProperty("velaKeyAlias") as String?)
                    ?: System.getenv("VELA_KEY_ALIAS")
                keyPassword = (project.findProperty("velaKeyPassword") as String?)
                    ?: System.getenv("VELA_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release")
                ?: if (allowDebugSigning) signingConfigs.getByName("debug") else null

            // Shrink, obfuscate, and strip the debug logging that used to ship
            // in release APKs (audit A-3). `proguard-rules.pro` carries the
            // keep rules for the one thing here resolved by name at runtime —
            // the JNI bridge — and the `-assumenosideeffects` block that
            // removes `Log.d`/`Log.v` and their string constants.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
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
    implementation("androidx.credentials:credentials:1.3.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.3.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.animation:animation")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-process:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.8")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("org.chromium.net:cronet-embedded:143.7445.0")
    // Google Drive appDataFolder backup for recovery Share 1 (SPEC.md §4.3):
    // Identity Authorization API for incremental `drive.appdata` scope
    // consent (no full Google Sign-In needed); Drive itself is called via
    // plain REST, matching this app's existing HTTP-client-free style.
    implementation("com.google.android.gms:play-services-auth:21.2.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.8.1")

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
        // Host-OS-aware NDK toolchain layout so the bridge builds on Windows
        // (local dev) and Linux/macOS (CI) alike.
        val osName = System.getProperty("os.name").lowercase()
        val isWindows = osName.contains("win")
        val hostPrefix = when {
            isWindows -> "windows-"
            osName.contains("mac") || osName.contains("darwin") -> "darwin-"
            else -> "linux-"
        }
        val exeSuffix = if (isWindows) ".exe" else ""
        val clangSuffix = if (isWindows) ".cmd" else ""

        val sdkDir = findAndroidSdkDir()
        val ndkDir = findAndroidNdkDir(sdkDir)
        val hostToolchain = ndkDir.resolve("toolchains/llvm/prebuilt")
            .listFiles()
            ?.firstOrNull { it.isDirectory && it.name.startsWith(hostPrefix) }
            ?: error("NDK LLVM '$hostPrefix' toolchain not found in ${ndkDir.absolutePath}")
        val binDir = hostToolchain.resolve("bin")
        val ar = binDir.resolve("llvm-ar$exeSuffix")
        val bridgeDir = rootProject.projectDir.parentFile.resolve("libVELA/vela-android-bridge")

        rustAndroidAbis.forEach { abi ->
            val linker = binDir.resolve("${abi.clangPrefix}-clang$clangSuffix")
            require(linker.isFile) { "Missing Android linker: ${linker.absolutePath}" }

            val cargo = ProcessBuilder("cargo", "build", "--release", "--target", abi.rustTarget)
                .directory(bridgeDir)
                .inheritIO()
            cargo.environment()["ANDROID_NDK_HOME"] = ndkDir.absolutePath
            // Pin the target dir to the bridge crate: the repo-root
            // .cargo/config.toml redirects it to VELA/target, and the Android
            // triples are unique to this build anyway.
            cargo.environment()["CARGO_TARGET_DIR"] = File(bridgeDir, "target").absolutePath
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

// Checked at task-graph time rather than during configuration: failing in the
// `android {}` block would break `assembleDebug` and even `gradlew tasks`,
// which is how an over-eager guard turns into "the build is broken" instead of
// "this release is unsigned" (audit A-3).
gradle.taskGraph.whenReady {
    val buildingRelease = allTasks.any { task ->
        task.project == project &&
            (task.name.startsWith("assembleRelease") || task.name.startsWith("bundleRelease"))
    }
    if (buildingRelease && !hasReleaseKeystore && !allowDebugSigning) {
        throw GradleException(
            "Release build requires a signing keystore. Set velaKeystoreFile / " +
                "VELA_KEYSTORE_FILE (plus password, alias, key password), or pass " +
                "-PvelaAllowDebugSigning=true to knowingly build a debug-signed release."
        )
    }
}
