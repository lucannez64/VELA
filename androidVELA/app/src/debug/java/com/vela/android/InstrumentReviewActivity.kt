package com.vela.android

import android.os.Bundle
import androidx.compose.ui.platform.LocalContext
import com.vela.android.autofill.AppAssociations
import com.vela.android.autofill.AppSignatures
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.vela.android.autofill.AutofillDatasetBuilder
import com.vela.android.core.PreservedJson
import com.vela.android.core.AuditEntry
import com.vela.android.core.VaultItem
import com.vela.android.core.VaultMeta
import com.vela.android.core.VaultOrganization
import com.vela.android.core.preserved
import com.vela.android.core.withMeta
import org.json.JSONArray
import org.json.JSONObject
import com.vela.android.sync.SyncSettings
import com.vela.android.sync.SyncState
import com.vela.android.ui.components.*
import com.vela.android.ui.screens.*
import com.vela.android.ui.theme.VelaColors
import com.vela.android.ui.theme.VelaThemes
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * Debug-only, fully interactive design review using the production screens
 * and sheets with synthetic data (the real app blocks screenshots).
 *
 * Mirrors docs/mobile-redesign-instrument.html: same sample items, real
 * navigation, favourites, reveal, copy, authenticator, and the actual
 * editor / share / choice sheets. Nothing touches a vault or the network.
 *
 *   adb shell am start -n com.vela.android/.InstrumentReviewActivity --es surface overview
 *   surfaces: overview vault detail generate more settings lock autofill passkey create error
 */
class InstrumentReviewActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val kind = intent.getStringExtra("surface") ?: "overview"
        setContent {
            var theme by remember { mutableStateOf(VelaThemes.VELA) }
            com.vela.android.ui.theme.VelaTheme(theme) {
                when (kind) {
                    "startup" -> StartupReview()
                    "autofill" -> AutofillReview { finish() }
                    "passkey", "create", "error", "working" -> PasskeyReview(kind) { finish() }
                    else -> AppReview(kind, theme) { theme = it }
                }
            }
        }
    }
}

private fun ago(days: Long) = Instant.now().minus(days, ChronoUnit.DAYS)

private const val FOLDER_WORK = "11111111-1111-4111-8111-111111111111"
private const val FOLDER_PERSONAL = "22222222-2222-4222-8222-222222222222"
private const val FOLDER_FINANCE = "33333333-3333-4333-8333-333333333333"
private const val TAG_2FA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
private const val TAG_SHARED = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

/** Synthetic organization so collections can be reviewed without a vault. */
private fun demoOrganization(): VaultOrganization {
    val now = Instant.now().toString()
    fun record(id: String, name: String, parent: String? = null) = JSONObject()
        .put("id", id).put("name", name)
        .apply { if (parent != null) put("parentId", parent) }
        .put("revision", JSONObject().put("counter", 1).put("deviceId", "review"))
        .put("createdAt", now).put("updatedAt", now)
    val folders = JSONArray()
        .put(record(FOLDER_WORK, "Work"))
        .put(record(FOLDER_PERSONAL, "Personal"))
        .put(record(FOLDER_FINANCE, "Finance", FOLDER_PERSONAL))
    val tags = JSONArray()
        .put(record(TAG_2FA, "2FA"))
        .put(record(TAG_SHARED, "Shared"))
        .put(record("c1111111-1111-4111-8111-111111111111", "Family"))
        .put(record("c2222222-2222-4222-8222-222222222222", "Important"))
        .put(record("c3333333-3333-4333-8333-333333333333", "Review later"))
        .put(record("c4444444-4444-4444-8444-444444444444", "Finance"))
        .put(record("c5555555-5555-4555-8555-555555555555", "Travel"))
        .put(record("c6666666-6666-4666-8666-666666666666", "Social"))
        .put(record("c7777777-7777-4777-8777-777777777777", "Work tools"))
        .put(record("c8888888-8888-4888-8888-888888888888", "Archive"))
        .put(record("c9999999-9999-4999-8999-999999999999", "Banking"))
        .put(record("d1111111-1111-4111-8111-111111111111", "Clients"))
        .put(record("d2222222-2222-4222-8222-222222222222", "Dev"))
        .put(record("d3333333-3333-4333-8333-333333333333", "Family shared"))
        .put(record("d4444444-4444-4444-8444-444444444444", "Insurance"))
        .put(record("d5555555-5555-4555-8555-555555555555", "Old accounts"))
        .put(record("d6666666-6666-4666-8666-666666666666", "Shopping"))
        .put(record("d7777777-7777-4777-8777-777777777777", "Streaming"))
        .put(record("d8888888-8888-4888-8888-888888888888", "Utilities"))
    return VaultOrganization(true, JSONObject().put("folders", folders).put("tags", tags).preserved())
}

private fun demoMutate(org: VaultOrganization, action: JSONObject): VaultOrganization {
    val root = org.json()
    fun list(key: String): List<JSONObject> {
        val array = root.optJSONArray(key) ?: return emptyList()
        return (0 until array.length()).map { array.getJSONObject(it) }
    }
    var folders = list("folders")
    var tags = list("tags")
    val id = action.optString("id")
    val now = Instant.now().toString()
    fun fresh(name: String): JSONObject = JSONObject()
        .put("id", java.util.UUID.randomUUID().toString())
        .put("name", name)
        .put("revision", JSONObject().put("counter", 1).put("deviceId", "review"))
        .put("createdAt", now).put("updatedAt", now)
    when (action.optString("operation")) {
        "createFolder" -> folders = folders + fresh(action.optString("name"))
            .apply { if (action.optString("parentId").isNotEmpty()) put("parentId", action.optString("parentId")) }
        "updateFolder" -> folders = folders.map { folder ->
            if (folder.optString("id") != id) folder else JSONObject(folder.toString())
                .put("name", action.optString("name"))
                .apply {
                    if (action.optString("parentId").isNotEmpty()) put("parentId", action.optString("parentId"))
                    else remove("parentId")
                }
        }
        "deleteFolder" -> folders = folders.filterNot { it.optString("id") == id }
        "createTag" -> tags = tags + fresh(action.optString("name"))
        "renameTag" -> tags = tags.map { tag ->
            if (tag.optString("id") != id) tag else JSONObject(tag.toString()).put("name", action.optString("name"))
        }
        "deleteTag" -> tags = tags.filterNot { it.optString("id") == id }
    }
    return VaultOrganization(true, JSONObject().put("folders", JSONArray(folders)).put("tags", JSONArray(tags)).preserved())
}

private fun demoRich(folder: String?, tags: List<String>, extras: JSONObject.() -> Unit = {}): PreservedJson =
    JSONObject().put("folderId", folder).put("tagIds", JSONArray(tags)).apply(extras).preserved()

private fun activitySamples(): List<AuditEntry> {
    fun ago(minutes: Long) = Instant.now().minus(minutes, ChronoUnit.MINUTES)
    return listOf(
        AuditEntry(timestamp = ago(6), actionType = "vault_unlocked", detail = "Fingerprint", deviceName = "This phone"),
        AuditEntry(timestamp = ago(22), actionType = "item_updated", detail = "Proton", deviceName = "This phone"),
        AuditEntry(timestamp = ago(95), actionType = "credential_released", detail = "proton.me · Firefox extension", deviceName = "Studio desktop"),
        AuditEntry(timestamp = ago(240), actionType = "share_sent", detail = "To jamie-morgan", deviceName = "This phone"),
        AuditEntry(timestamp = ago(1500), actionType = "vault_sync", detail = "3 chunks", deviceName = "This phone"),
        AuditEntry(timestamp = ago(1560), actionType = "item_added", detail = "Figma", deviceName = "Studio desktop"),
        AuditEntry(timestamp = ago(1620), actionType = "device_revoked", detail = "Old tablet", deviceName = "This phone"),
        AuditEntry(timestamp = ago(2900), actionType = "share_link_created", detail = "Studio Wi-Fi · expires in 2 days", deviceName = "This phone"),
        AuditEntry(timestamp = ago(3100), actionType = "breach_passwords_checked", detail = "2 exposed passwords", deviceName = "This phone"),
    )
}

private fun sampleItems(): List<VaultItem> = listOf(
    VaultItem.Login(VaultMeta(name = "Proton", favorite = true, updatedAt = ago(2), richFields = demoRich(FOLDER_WORK, listOf(TAG_2FA, TAG_SHARED)) {
        put("customFields", JSONArray().put(JSONObject()
            .put("id", java.util.UUID.randomUUID().toString())
            .put("label", "Recovery email")
            .put("type", "text")
            .put("value", "backup@example.test")))
        put("additionalUrls", JSONArray().put(JSONObject()
            .put("id", java.util.UUID.randomUUID().toString())
            .put("url", "https://account.proton.me/login")
            .put("match", "origin")))
    }), "https://proton.me", "alex@example.test",
        "Example-only!42-Proton", totp = "JBSWY3DPEHPK3PXP"),
    VaultItem.Login(VaultMeta(name = "GitHub", favorite = true, updatedAt = ago(5), richFields = demoRich(FOLDER_WORK, listOf(TAG_2FA))), "https://github.com", "alex-demo", "Example-only!42-GitHub"),
    VaultItem.Login(VaultMeta(name = "Figma", updatedAt = ago(40), richFields = demoRich(FOLDER_PERSONAL, emptyList())), "https://figma.com", "alex@studio.example", "summer24"),
    VaultItem.CreditCard(VaultMeta(name = "Everyday", favorite = true, updatedAt = ago(12)), "Alex Demo", "4242424242424242", "08/29", "123"),
    VaultItem.SecureNote(VaultMeta(name = "Recovery codes", updatedAt = ago(90)), "Example recovery codes\nFAKE-CODE-1234\nFAKE-CODE-5678"),
    VaultItem.Login(VaultMeta(name = "Music account", updatedAt = ago(400)), "https://music.example", "alex@example.test", "summer24"),
    VaultItem.Passkey(VaultMeta(name = "Studio passkey", updatedAt = ago(20)), rpId = "studio.example", userName = "alex@studio.example"),
)

@Composable
private fun AppReview(start: String, theme: String, onTheme: (String) -> Unit) {
    val context = LocalContext.current
    var items by remember { mutableStateOf(sampleItems()) }
    var page by remember { mutableStateOf(if (start == "app") "overview" else start) }
    var detailId by remember { mutableStateOf(items.first().id) }
    var favoritesOnly by remember { mutableStateOf(false) }
    var attentionOnly by remember { mutableStateOf(false) }
    var sheet by remember { mutableStateOf<String?>(null) }
    var prefillPassword by remember { mutableStateOf("") }
    var autoLock by remember { mutableIntStateOf(5) }
    var clipboard by remember { mutableIntStateOf(15) }
    var organization by remember { mutableStateOf(demoOrganization()) }
    val toast = LocalInstrumentToast.current
    val sync = SyncState(lastSyncedAt = "now")
    val detail = items.find { it.id == detailId }
    fun open(item: VaultItem) { detailId = item.id; page = "detail" }
    fun vault(fav: Boolean = false, attention: Boolean = false) { favoritesOnly = fav; attentionOnly = attention; page = "vault" }
    val root = when (page) { "overview", "vault", "generate" -> page; "detail" -> "vault"; else -> "more" }
    if (page != "overview" && sheet == null) BackHandler { page = if (page == "detail") "vault" else "overview" }

    Box(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).safeDrawingPadding()) {
        Column(Modifier.fillMaxSize()) {
            AnimatedContent(page, Modifier.weight(1f),
                transitionSpec = { (fadeIn(tween(250)) + slideInVertically(tween(250, easing = InstrumentEase)) { it / 60 }) togetherWith fadeOut(tween(120)) },
                label = "page") { current ->
                when (current) {
                    "overview" -> OverviewScreen(items, sync, ::open, { vault() }, { vault(fav = true) }, { page = "generate" }, { page = "lock" },
                        onAttention = { vault(attention = true) })
                    "vault" -> VaultBrowserScreen(items, items.size, ::open, { prefillPassword = ""; sheet = "add" }, { page = "lock" },
                        initialFavoritesOnly = favoritesOnly, initialAttentionOnly = attentionOnly, syncState = sync,
                        organization = organization, onEnableCollections = {},
                        onMutateOrganization = { organization = demoMutate(organization, it) })
                    "generate" -> GeneratorScreen({ pw -> prefillPassword = pw; sheet = "add" }, sync)
                    "more" -> MoreScreen(null, { route ->
                        when (route) {
                            "favorites" -> vault(fav = true)
                            "attention" -> vault(attention = true)
                            "settings" -> page = "settings"
                            "audit_log" -> page = "activity"
                            else -> toast.show("Sharing and devices use the real account. Not shown in review.")
                        }
                    }, { page = "lock" }, sync, favorites = items.count { it.favorite },
                        attention = items.filterIsInstance<VaultItem.Login>().count { it.password == "summer24" })
                    "activity" -> AuditLogScreen({ page = "more" }, activitySamples())
                    "settings" -> SettingsScreen("", SyncSettings(), sync, null, {}, {}, {}, {},
                        { _, _ -> }, { _, _ -> }, {}, {}, {}, {}, {}, { page = "lock" }, {},
                        autoLock, clipboard, { autoLock = it }, { clipboard = it }, theme, onTheme, { page = "more" }, biometricUnlockEnabled = false)
                    "detail" -> ItemDetailScreen(detail, { page = "vault" },
                        onEdit = { sheet = "edit" },
                        onDelete = { items = items.filterNot { it.id == detailId }; page = "vault"; toast.show("Deleted from this review.") },
                        onShare = { sheet = "share" },
                        onToggleFavorite = { item -> items = items.map { if (it.id == item.id) it.withMeta { m -> m.copy(favorite = !m.favorite) } else it } },
                        organization = organization,
                        linkedApps = { login ->
                            LinkedAppsSection(login.appIds, onLink = { pkg, pin ->
                                val cert = if (pin) AppSignatures.sha256(context, pkg).firstOrNull() else null
                                if (pin && cert == null) false else {
                                    val link = AppAssociations.appUri(pkg, cert)
                                    items = items.map { current ->
                                        if (current is VaultItem.Login && current.id == login.id)
                                            current.copy(appIds = current.appIds.filterNot { AppAssociations.packageFromUri(it) == pkg } + link)
                                        else current
                                    }
                                    true
                                }
                            }, onUnlink = { link ->
                                items = items.map { current -> if (current is VaultItem.Login && current.id == login.id)
                                    current.copy(appIds = current.appIds - link) else current }
                            })
                        })
                    "lock" -> UnlockScreen(true, true, { page = "overview"; toast.show("Unlocked.") }, { page = "overview" })
                }
            }
            if (page in listOf("overview", "vault", "generate", "more")) InstrumentDock(
                listOf(InstrumentDockItem("overview", "Overview", InstrumentIcons.Grid), InstrumentDockItem("vault", "Vault", InstrumentIcons.Vault),
                    InstrumentDockItem("generate", "Generate", InstrumentIcons.Dice), InstrumentDockItem("more", "More", InstrumentIcons.Dots)),
                root, { route -> if (route == "vault") vault() else page = route })
        }

        if (sheet == "add" || sheet == "edit") AddItemScreen(
            editItem = if (sheet == "edit") detail else null,
            initialPassword = prefillPassword,
            readOnly = false,
            organization = organization,
            onBack = { sheet = null },
            onSave = { item ->
                items = if (sheet == "edit") items.map { if (it.id == detailId) item else it } else items + item
                sheet = null; toast.show("Saved in this review.")
            }
        )
        ShareItemSheet(sheet == "share", detail?.name ?: "item", { sheet = null }) { share ->
            sheet = null
            toast.show(if (share.toUser) "Shared with ${share.recipient}." else "Link ready · expires in ${share.expiry}.")
        }
    }
}

@Composable
private fun AutofillReview(onDone: () -> Unit) {
    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).safeDrawingPadding().padding(20.dp)) {
        InstrumentHeading("Debug / Synthetic review", "Autofill suggestions.", "Rendered with the production RemoteViews layout.")
        AndroidView(factory = { context -> AutofillDatasetBuilder.presentation(context, "Example login", "example.test · alex@example.test").apply(context, null) })
        Spacer(Modifier.height(12.dp))
        AndroidView(factory = { context -> AutofillDatasetBuilder.presentation(context, "Everyday card", "•••• 4242 · 08/29").apply(context, null) })
        Spacer(Modifier.height(12.dp))
        AndroidView(factory = { context -> AutofillDatasetBuilder.presentation(context, "Unlock VELA", "Unlock your vault to fill this form").apply(context, null) })
        Spacer(Modifier.height(24.dp))
        InstrumentPill("Done", onDone, Modifier.fillMaxWidth(), style = PillStyle.Primary)
    }
}

@Composable
private fun PasskeyReview(kind: String, onDone: () -> Unit) {
    val toast = LocalInstrumentToast.current
    CredentialConfirmation(
        title = if (kind == "create") "Create a passkey in VELA" else "Sign in with a VELA passkey",
        relyingParty = "example.test", account = "alex@example.test",
        detail = "Synthetic design review · no authentication request or signature.",
        error = if (kind == "error") "Verification was cancelled. You can try again." else null,
        busy = kind == "working", approveEnabled = kind != "working",
        approveLabel = if (kind == "create") "Create passkey" else "Sign in with passkey",
        onApprove = { toast.show("Design review only. No passkey was used.") },
        onCancel = onDone,
    )
}

/** Resource-only preview of the native launch artwork; it never opens a vault. */
@Composable
private fun StartupReview() {
    AndroidView(modifier = Modifier.fillMaxSize(), factory = { context ->
        val density = context.resources.displayMetrics.density
        fun dp(value: Int) = (value * density).toInt()
        android.widget.FrameLayout(context).apply {
            setBackgroundColor(android.graphics.Color.rgb(11, 11, 16))
            addView(android.widget.ImageView(context).apply {
                contentDescription = "VELA startup mark"
                setImageResource(com.vela.android.R.drawable.vela_startup_animated)
                post { (drawable as? android.graphics.drawable.Animatable)?.start() }
            }, android.widget.FrameLayout.LayoutParams(dp(288), dp(288), android.view.Gravity.CENTER))
            addView(android.widget.ImageView(context).apply {
                contentDescription = "VELA"
                setImageResource(com.vela.android.R.drawable.vela_wordmark)
            }, android.widget.FrameLayout.LayoutParams(dp(200), dp(80), android.view.Gravity.BOTTOM or android.view.Gravity.CENTER_HORIZONTAL).apply {
                bottomMargin = dp(28)
            })
        }
    })
}
