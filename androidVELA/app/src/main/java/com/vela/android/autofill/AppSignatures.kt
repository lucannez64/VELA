package com.vela.android.autofill

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest

/**
 * SHA-256 fingerprints of the certificates an installed app is signed with,
 * formatted `AB:CD:…` to match how sites and allowlists publish them.
 *
 * The fingerprint is what makes a package name mean something. Anyone can
 * publish an APK called `com.android.chrome` to a third-party store; nobody
 * else can sign it with Google's key. Both [AssetLinksVerifier] and
 * [BrowserAllowlist] answer "is this really that app?" the same way, so they
 * ask the same question here.
 */
object AppSignatures {

    fun sha256(context: Context, packageName: String): Set<String> = runCatching {
        val pm = context.packageManager
        val signatures: Array<Signature> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signing = pm.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            ).signingInfo
            when {
                signing == null -> emptyArray()
                // Rotated keys count: the app is still the one that was vouched for.
                signing.hasMultipleSigners() -> signing.apkContentsSigners ?: emptyArray()
                else -> signing.signingCertificateHistory ?: emptyArray()
            }
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures ?: emptyArray()
        }

        signatures.map { signature ->
            MessageDigest.getInstance("SHA-256")
                .digest(signature.toByteArray())
                .joinToString(":") { byte -> "%02X".format(byte) }
        }.toSet()
    }.getOrDefault(emptySet())

    /** `AB:CD:…` uppercase, however the source chose to write it. */
    fun normalize(fingerprint: String): String? =
        fingerprint.trim().uppercase(java.util.Locale.US).replace(" ", "").takeIf { it.isNotEmpty() }
}
