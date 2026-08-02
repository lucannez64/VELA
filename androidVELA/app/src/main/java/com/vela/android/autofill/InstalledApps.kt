package com.vela.android.autofill

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import java.util.Locale

/**
 * The installed apps a user can link a login to.
 *
 * Only launcher-visible apps, found through a `<queries>` intent filter rather
 * than `QUERY_ALL_PACKAGES`: a password manager has no business enumerating
 * every package on the device, and the apps a user would recognise well enough
 * to grant a credential to are exactly the ones with a launcher icon.
 *
 * An app that is not visible to us still resolves to its package name, so a link
 * made on another device — or to something since uninstalled — is always shown
 * rather than silently disappearing from the list.
 */
object InstalledApps {

    data class Entry(
        val packageName: String,
        val label: String,
        val icon: Drawable?,
    )

    fun launchable(context: Context): List<Entry> {
        val pm = context.packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = runCatching {
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(intent, 0)
        }.getOrDefault(emptyList())

        return resolved
            .mapNotNull { it.activityInfo?.applicationInfo }
            .distinctBy { it.packageName }
            .filter { it.packageName != context.packageName }
            .map { info ->
                Entry(
                    packageName = info.packageName,
                    label = runCatching { pm.getApplicationLabel(info).toString() }
                        .getOrDefault(info.packageName),
                    icon = runCatching { pm.getApplicationIcon(info) }.getOrNull(),
                )
            }
            .sortedBy { it.label.lowercase(Locale.US) }
    }

    /** Label and icon for one package, falling back to the package name. */
    fun describe(context: Context, packageName: String): Entry {
        val pm = context.packageManager
        return runCatching {
            @Suppress("DEPRECATION")
            val info = pm.getApplicationInfo(packageName, 0)
            Entry(
                packageName = packageName,
                label = pm.getApplicationLabel(info).toString(),
                icon = runCatching { pm.getApplicationIcon(info) }.getOrNull(),
            )
        }.getOrDefault(Entry(packageName, packageName, null))
    }

    /** Whether the app is installed and visible — a link to something absent is worth showing as such. */
    fun isInstalled(context: Context, packageName: String): Boolean = runCatching {
        @Suppress("DEPRECATION")
        context.packageManager.getApplicationInfo(packageName, 0)
        true
    }.getOrDefault(false)
}
