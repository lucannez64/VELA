package com.vela.android.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.os.Build
import android.text.InputType
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.Field
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.Presentations
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.vela.android.MainActivity
import com.vela.android.R
import com.vela.android.core.VaultItem
import com.vela.android.core.VaultMeta
import com.vela.android.core.VelaRepositories
import java.time.Instant
import java.util.Locale

class VelaAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: android.os.CancellationSignal,
        callback: FillCallback
    ) {
        try {
            val structure = request.fillContexts.lastOrNull()?.structure
            if (structure == null) {
                Log.d(TAG, "onFillRequest: no structure")
                callback.onSuccess(null)
                return
            }

            val fields = AutofillStructureParser.parse(structure)
            val fillable = AutofillFieldSet.from(fields)
            Log.d(TAG, "onFillRequest: fields=${fields.size} usernames=${fillable.usernameFields.size} passwords=${fillable.passwordFields.size}")

            if (!fillable.canFill && !fillable.isPaymentForm) {
                Log.d(TAG, "onFillRequest: nothing fillable")
                callback.onSuccess(null)
                return
            }

            if (!VelaRepositories.security.session.value.unlocked) {
                Log.d(TAG, "onFillRequest: vault locked, showing unlock prompt")
                val lockedPackage = structure.activityComponent?.packageName
                callback.onSuccess(
                    buildLockedResponse(fillable, fields.claimedWebDomain(), lockedPackage)
                )
                return
            }

            val packageName = structure.activityComponent?.packageName
            // The claimed domain is passed through as claimed: whether it may be
            // believed is [AutofillMatcher]'s decision, not ours. Do not collapse
            // it onto the package name — that is what let any app ask for any
            // site's credentials (audit A-2).
            val responseBuilder = FillResponse.Builder()
            var added = 0

            if (fillable.canFill) {
                val candidates = VelaRepositories.vault
                    .findAutofillLogins(fields.claimedWebDomain(), packageName)
                // NOTE: never log `domain` or candidate names/urls/usernames here —
                // logcat is readable via ADB / READ_LOGS and leaks which sites the
                // user has credentials for.
                Log.d(TAG, "onFillRequest: login candidates=${candidates.size}")
                responseBuilder.setSaveInfo(buildSaveInfo(fillable))
                candidates.take(MAX_DATASETS).forEachIndexed { index, login ->
                    Log.d(TAG, "onFillRequest: building login dataset $index")
                    val dataset = AutofillDatasetBuilder.buildLoginDataset(this, fillable, login)
                    if (dataset != null) {
                        responseBuilder.addDataset(dataset)
                        added++
                    }
                }
            }

            // Cards are not scoped to a site: a payment form may be filled with
            // any stored card. Nothing is saved back (fill-only), so a payment
            // form never gets SaveInfo.
            if (fillable.isPaymentForm) {
                val cards = VelaRepositories.vault.items.value.filterIsInstance<VaultItem.CreditCard>()
                Log.d(TAG, "onFillRequest: cards=${cards.size}")
                cards.take(MAX_DATASETS).forEach { card ->
                    AutofillDatasetBuilder.buildCardDataset(this, fillable, card)?.let { dataset ->
                        responseBuilder.addDataset(dataset)
                        added++
                    }
                }
            }

            // A login form must still get a response even with no matching
            // logins, because the response carries the save prompt. A pure
            // payment form with no card to offer gets nothing.
            if (added == 0 && !fillable.canFill) {
                Log.d(TAG, "onFillRequest: nothing to offer")
                callback.onSuccess(null)
                return
            }
            Log.d(TAG, "onFillRequest: sending response with $added datasets")
            callback.onSuccess(responseBuilder.build())
        } catch (e: Exception) {
            Log.e(TAG, "onFillRequest crashed", e)
            callback.onSuccess(null)
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        try {
            if (!VelaRepositories.security.session.value.unlocked) {
                callback.onFailure("Unlock VELA before saving credentials")
                return
            }

            val structure = request.fillContexts.lastOrNull()?.structure
            if (structure == null) {
                callback.onFailure("No form data to save")
                return
            }

            val fields = AutofillStructureParser.parse(structure)
            val fillable = AutofillFieldSet.from(fields)
            val username = fillable.usernameFields.firstNotNullOfOrNull { id -> fields.valueFor(id) }
            val password = fillable.passwordFields.firstNotNullOfOrNull { id -> fields.valueFor(id) }
            if (password.isNullOrBlank()) {
                callback.onFailure("No password found")
                return
            }

            val claimedDomain = fields.claimedWebDomain()
            val packageName = structure.activityComponent?.packageName
            val fromBrowser = VelaRepositories.vault.isTrustedBrowser(packageName)

            // What the login is *for*. A browser is showing a site, so the site is
            // the target; anything else is an app, and the URL it claims is not
            // ours to believe — but the package it runs as is.
            val target = when {
                fromBrowser -> claimedDomain ?: packageName.orEmpty()
                packageName != null -> AppAssociations.curatedDomain(packageName) ?: packageName
                else -> claimedDomain.orEmpty()
            }
            if (target.isBlank()) {
                callback.onFailure("No app or website target found")
                return
            }

            // Saving a password *from* an app is the user telling us these belong
            // together — the confirmation the association needs (audit A-2). It is
            // recorded on the item so the pairing survives without any guessing,
            // pinned to the signing key the app has right now so the grant does
            // not transfer if the package later ships from someone else. The user
            // can relax that to name-only from the item screen.
            val appIds = if (!fromBrowser && packageName != null) {
                val fingerprint = AppSignatures.sha256(this, packageName).firstOrNull()
                listOf(AppAssociations.appUri(packageName, fingerprint))
            } else {
                emptyList()
            }

            val existing = VelaRepositories.vault
                .findAutofillLogins(claimedDomain, packageName)
                .firstOrNull { it.username.equals(username.orEmpty(), ignoreCase = true) }
            val now = Instant.now()
            if (existing == null) {
                VelaRepositories.vault.addItem(
                    VaultItem.Login(
                        meta = VaultMeta(
                            name = displayNameForTarget(target),
                            createdAt = now,
                            updatedAt = now,
                            lastModifiedDevice = "android-local"
                        ),
                        url = target,
                        username = username.orEmpty(),
                        password = password,
                        appIds = appIds
                    )
                )
                // NOTE: never log `target` (domain/package) or the item name here —
                // logcat is readable via ADB / READ_LOGS and leaks which sites the
                // user has credentials for.
                Log.d(TAG, "onSaveRequest: created new login")
            } else {
                val mergedAppIds = (existing.appIds + appIds).distinct()
                val passwordChanged = existing.password != password
                val linkAdded = mergedAppIds.size != existing.appIds.size
                if (passwordChanged || linkAdded) {
                    VelaRepositories.vault.updateItem(
                        existing.copy(
                            password = password,
                            appIds = mergedAppIds,
                            meta = existing.meta.copy(
                                updatedAt = now,
                                lastModifiedDevice = "android-local"
                            )
                        )
                    )
                    Log.d(TAG, "onSaveRequest: updated existing login")
                } else {
                    Log.d(TAG, "onSaveRequest: unchanged login, ignored")
                }
            }
            callback.onSuccess()
        } catch (e: Exception) {
            Log.e(TAG, "onSaveRequest crashed", e)
            callback.onFailure(e.message ?: "Save failed")
        }
    }

    companion object {
        private const val TAG = "VelaAutofillService"
        private const val MAX_DATASETS = 5
    }

    private fun buildLockedResponse(fields: AutofillFieldSet, domain: String?, packageName: String?): FillResponse {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(MainActivity.EXTRA_AUTOFILL_UNLOCK, true)
            .putParcelableArrayListExtra(MainActivity.EXTRA_AUTOFILL_USERNAME_IDS, ArrayList(fields.usernameFields))
            .putParcelableArrayListExtra(MainActivity.EXTRA_AUTOFILL_PASSWORD_IDS, ArrayList(fields.passwordFields))
            .putParcelableArrayListExtra(MainActivity.EXTRA_AUTOFILL_CARD_NUMBER_IDS, ArrayList(fields.cardNumberFields))
            .putParcelableArrayListExtra(MainActivity.EXTRA_AUTOFILL_CARD_EXPIRY_IDS, ArrayList(fields.cardExpiryFields))
            .putParcelableArrayListExtra(MainActivity.EXTRA_AUTOFILL_CARD_EXP_MONTH_IDS, ArrayList(fields.cardExpiryMonthFields))
            .putParcelableArrayListExtra(MainActivity.EXTRA_AUTOFILL_CARD_EXP_YEAR_IDS, ArrayList(fields.cardExpiryYearFields))
            .putParcelableArrayListExtra(MainActivity.EXTRA_AUTOFILL_CARD_CVV_IDS, ArrayList(fields.cardCvvFields))
            .putParcelableArrayListExtra(MainActivity.EXTRA_AUTOFILL_CARD_NAME_IDS, ArrayList(fields.cardNameFields))
            .putExtra(MainActivity.EXTRA_AUTOFILL_DOMAIN, domain)
            .putExtra(MainActivity.EXTRA_AUTOFILL_PACKAGE, packageName)
            // Proof this intent came from us and not from any app that noticed
            // MainActivity is exported (audit A-1).
            .putExtra(MainActivity.EXTRA_AUTOFILL_TOKEN, AutofillUnlockTokens.issue())
        val pendingIntent = PendingIntent.getActivity(
            this,
            1001,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val presentation = AutofillDatasetBuilder.presentation(this, "Unlock VELA", "Open vault to fill passwords")
        val builder = FillResponse.Builder()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            builder.setAuthentication(fields.allIds(), pendingIntent.intentSender, AutofillDatasetBuilder.presentations(presentation))
        } else {
            @Suppress("DEPRECATION")
            builder.setAuthentication(fields.allIds(), pendingIntent.intentSender, presentation)
        }
        return builder.build()
    }

    private fun buildSaveInfo(fields: AutofillFieldSet): SaveInfo {
        return SaveInfo.Builder(
            SaveInfo.SAVE_DATA_TYPE_PASSWORD,
            fields.loginIds()
        )
            .setDescription("Save login in VELA")
            .build()
    }

    private fun displayNameForTarget(target: String): String {
        val host = target
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
            .removePrefix("www.")
        return host.split(".", "-")
            .filter { it.isNotBlank() && it !in setOf("com", "org", "net", "app") }
            .joinToString(" ") { word -> word.replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.US) else it.toString() } }
            .ifBlank { host.ifBlank { "Saved Login" } }
    }
}

/**
 * Builds Autofill datasets/responses from a resolved [VaultItem.Login]. Shared
 * between [VelaAutofillService] (has the AssistStructure) and [MainActivity]
 * (post-unlock: no AssistStructure, only the [AutofillFieldSet] and domain/
 * package captured before the vault was locked) so both fill the same way.
 */
object AutofillDatasetBuilder {
    private const val TAG = "AutofillDatasetBuilder"

    fun buildFillResponse(
        context: Context,
        fields: AutofillFieldSet,
        domain: String?,
        packageName: String?,
        maxDatasets: Int = 5
    ): FillResponse? {
        if (!fields.canFill && !fields.isPaymentForm) return null

        val builder = FillResponse.Builder()
        var added = 0
        if (fields.canFill) {
            val candidates = VelaRepositories.vault.findAutofillLogins(domain, packageName)
            candidates.take(maxDatasets).forEach { login ->
                val dataset = buildLoginDataset(context, fields, login)
                if (dataset != null) {
                    builder.addDataset(dataset)
                    added++
                }
            }
        }
        if (fields.isPaymentForm) {
            VelaRepositories.vault.items.value
                .filterIsInstance<VaultItem.CreditCard>()
                .take(maxDatasets)
                .forEach { card ->
                    buildCardDataset(context, fields, card)?.let { dataset ->
                        builder.addDataset(dataset)
                        added++
                    }
                }
        }
        if (added == 0) return null
        return builder.build()
    }

    fun buildLoginDataset(context: Context, fields: AutofillFieldSet, login: VaultItem.Login): Dataset? {
        return try {
            val presentation = presentation(context, login.name, login.username)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val presentations = presentations(presentation)
                val dataset = Dataset.Builder(presentations)
                fields.usernameFields.forEach { id ->
                    if (login.username.isNotBlank()) {
                        dataset.setField(id, autofillField(login.username, presentations))
                    }
                }
                fields.passwordFields.forEach { id ->
                    if (login.password.isNotBlank()) {
                        dataset.setField(id, autofillField(login.password, presentations))
                    }
                }
                dataset.build()
            } else {
                legacyDataset(fields, login, presentation)
            }
        } catch (e: Exception) {
            Log.e(TAG, "buildLoginDataset failed", e)
            null
        }
    }

    fun buildCardDataset(context: Context, fields: AutofillFieldSet, card: VaultItem.CreditCard): Dataset? {
        return try {
            val presentation = presentation(context, card.name, cardSubtitle(card))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val presentations = presentations(presentation)
                val dataset = Dataset.Builder(presentations)
                fields.cardNameFields.forEach { id ->
                    if (card.cardholderName.isNotBlank()) {
                        dataset.setField(id, autofillField(card.cardholderName, presentations))
                    }
                }
                fields.cardNumberFields.forEach { id ->
                    if (card.cardNumber.isNotBlank()) {
                        dataset.setField(id, autofillField(card.cardNumber, presentations))
                    }
                }
                parseExpiry(card.expiration)?.let { exp ->
                    fields.cardExpiryFields.forEach { dataset.setField(it, autofillField(exp.mmyy, presentations)) }
                    fields.cardExpiryMonthFields.forEach { dataset.setField(it, autofillField(exp.mm, presentations)) }
                    fields.cardExpiryYearFields.forEach { dataset.setField(it, autofillField(exp.year, presentations)) }
                }
                fields.cardCvvFields.forEach { id ->
                    if (card.cvv.isNotBlank()) {
                        dataset.setField(id, autofillField(card.cvv, presentations))
                    }
                }
                dataset.build()
            } else {
                legacyCardDataset(fields, card, presentation)
            }
        } catch (e: Exception) {
            Log.e(TAG, "buildCardDataset failed", e)
            null
        }
    }

    @Suppress("DEPRECATION")
    private fun legacyCardDataset(fields: AutofillFieldSet, card: VaultItem.CreditCard, presentation: RemoteViews): Dataset {
        val dataset = Dataset.Builder(presentation)
        fun set(ids: List<AutofillId>, value: String) {
            if (value.isNotBlank()) {
                ids.forEach { dataset.setValue(it, AutofillValue.forText(value), presentation) }
            }
        }
        set(fields.cardNameFields, card.cardholderName)
        set(fields.cardNumberFields, card.cardNumber)
        parseExpiry(card.expiration)?.let { exp ->
            set(fields.cardExpiryFields, exp.mmyy)
            set(fields.cardExpiryMonthFields, exp.mm)
            set(fields.cardExpiryYearFields, exp.year)
        }
        set(fields.cardCvvFields, card.cvv)
        return dataset.build()
    }

    private fun cardSubtitle(card: VaultItem.CreditCard): String {
        val digits = card.cardNumber.filter { it.isDigit() }
        return if (digits.length >= 4) "•••• ${digits.takeLast(4)}" else card.cardholderName
    }

    private data class CardExpiry(val mm: String, val yy: String, val year: String, val mmyy: String)

    /**
     * VELA stores the expiry as the user typed it (`12/29`, `1229`, `12/2029`).
     * Digits are normalized so a combined field gets `MM/YY` and split
     * month/year fields get their own half.
     */
    private fun parseExpiry(value: String): CardExpiry? {
        val digits = value.filter { it.isDigit() }
        if (digits.length < 3) return null
        val mm: String
        val yy: String
        val year: String
        when (digits.length) {
            4 -> { mm = digits.substring(0, 2); yy = digits.substring(2, 4); year = "20$yy" }
            6 -> { mm = digits.substring(0, 2); year = digits.substring(2, 6); yy = year.substring(2, 4) }
            3 -> { mm = "0${digits.substring(0, 1)}"; yy = digits.substring(1, 3); year = "20$yy" }
            else -> { mm = digits.substring(0, 2); yy = digits.takeLast(2); year = "20$yy" }
        }
        if ((mm.toIntOrNull() ?: return null) !in 1..12) return null
        return CardExpiry(mm, yy, year, "$mm/$yy")
    }

    fun presentation(context: Context, title: String, subtitle: String?): RemoteViews {
        return RemoteViews(context.packageName, R.layout.autofill_dataset).apply {
            setTextViewText(R.id.title, title)
            setTextViewText(R.id.subtitle, subtitle ?: context.getString(R.string.autofill_service_label))
        }
    }

    @android.annotation.TargetApi(Build.VERSION_CODES.TIRAMISU)
    fun presentations(presentation: RemoteViews): Presentations {
        return Presentations.Builder()
            .setMenuPresentation(presentation)
            .setDialogPresentation(presentation)
            .build()
    }

    @android.annotation.TargetApi(Build.VERSION_CODES.TIRAMISU)
    private fun autofillField(value: String, presentations: Presentations): Field {
        return Field.Builder()
            .setValue(AutofillValue.forText(value))
            .setPresentations(presentations)
            .build()
    }

    @Suppress("DEPRECATION")
    private fun legacyDataset(fields: AutofillFieldSet, login: VaultItem.Login, presentation: RemoteViews): Dataset {
        val dataset = Dataset.Builder(presentation)
        fields.usernameFields.forEach { id ->
            if (login.username.isNotBlank()) {
                dataset.setValue(id, AutofillValue.forText(login.username), presentation)
            }
        }
        fields.passwordFields.forEach { id ->
            if (login.password.isNotBlank()) {
                dataset.setValue(id, AutofillValue.forText(login.password), presentation)
            }
        }
        return dataset.build()
    }
}

// ---------------------------------------------------------------------------
// Field parsing and detection — aligned with the browser extension logic
// ---------------------------------------------------------------------------

private val USERNAME_FIELD_NAMES = listOf(
    "username", "user name", "userid", "user id",
    "customer id", "login id", "login",
    "benutzername", "benutzer name", "benutzerid", "benutzer id",
    "email", "email address", "e-mail", "e-mail address",
    "email adresse", "e-mail adresse"
)

private val PASSWORD_KEYWORDS = listOf("password", "pass", "pwd")

/**
 * Normalizes a string for fuzzy matching by stripping all non-alphanumeric
 * characters and lowercasing — exactly like the extension does.
 */
private fun normalizeForFuzzy(value: String): String {
    return value.replace(Regex("[^a-zA-Z0-9]"), "").lowercase()
}

/**
 * Checks whether [normalizedCriteria] contains [normalizedOption] or vice-versa.
 */
private fun fuzzyMatch(normalizedCriteria: String, normalizedOption: String): Boolean {
    return normalizedCriteria.contains(normalizedOption) || normalizedOption.contains(normalizedCriteria)
}

/**
 * Extension-style field descriptor built from an AssistStructure.ViewNode.
 */
data class ParsedAutofillField(
    val autofillId: AutofillId,
    val htmlName: String?,
    val htmlId: String?,
    val htmlType: String?,
    val htmlAutocomplete: String?,
    val xWebkitAutocomplete: String?,
    val xAutocomplete: String?,
    val androidHint: String?,
    val idEntry: String?,
    val inputType: Int,
    val webDomain: String?,
    val valueText: String?
) {
    /**
     * The effective autocomplete hint, mirroring the extension's priority:
     * 1. autocomplete  2. x-webkit-autocomplete  3. x-autocomplete
     */
    val effectiveAutocomplete: String?
        get() = htmlAutocomplete ?: xWebkitAutocomplete ?: xAutocomplete

    /**
     * Collects every piece of text we can use for fuzzy heuristics.
     */
    fun fuzzyCriteria(): List<String> {
        return listOfNotNull(htmlName, htmlId, androidHint, idEntry)
            .filter { it.isNotBlank() }
    }
}

object AutofillStructureParser {
    fun parse(structure: AssistStructure): List<ParsedAutofillField> {
        val result = mutableListOf<ParsedAutofillField>()
        for (windowIndex in 0 until structure.windowNodeCount) {
            val window = structure.getWindowNodeAt(windowIndex)
            visit(window.rootViewNode, result)
        }
        return result
    }

    private fun visit(node: AssistStructure.ViewNode, result: MutableList<ParsedAutofillField>) {
        val autofillId = node.autofillId
        if (autofillId != null && node.autofillType != android.view.View.AUTOFILL_TYPE_NONE) {
            val attrs = node.htmlInfo?.attributes?.toList() ?: emptyList()

            val htmlName = attrs.firstOrNull { it.first == "name" }?.second
            val htmlId = attrs.firstOrNull { it.first == "id" }?.second
            val htmlType = attrs.firstOrNull { it.first == "type" }?.second
            val htmlAutocomplete = attrs.firstOrNull { it.first == "autocomplete" }?.second
            val xWebkitAutocomplete = attrs.firstOrNull { it.first == "x-webkit-autocomplete" }?.second
            val xAutocomplete = attrs.firstOrNull { it.first == "x-autocomplete" }?.second

            result += ParsedAutofillField(
                autofillId = autofillId,
                htmlName = htmlName,
                htmlId = htmlId,
                htmlType = htmlType,
                htmlAutocomplete = htmlAutocomplete,
                xWebkitAutocomplete = xWebkitAutocomplete,
                xAutocomplete = xAutocomplete,
                androidHint = node.hint?.toString(),
                idEntry = node.idEntry,
                inputType = node.inputType,
                webDomain = node.webDomain,
                valueText = node.autofillValue?.takeIf { it.isText }?.textValue?.toString()
            )
        }

        for (index in 0 until node.childCount) {
            visit(node.getChildAt(index), result)
        }
    }
}

/**
 * The `webDomain` the filled app claims, if any.
 *
 * Returned raw and unfiltered on purpose: any app can set this field, so
 * deciding whether to believe it belongs in one place ([AutofillMatcher]), not
 * scattered across every caller.
 */
private fun List<ParsedAutofillField>.claimedWebDomain(): String? =
    firstNotNullOfOrNull { it.webDomain?.takeIf { domain -> domain.isNotBlank() } }

private fun List<ParsedAutofillField>.valueFor(id: AutofillId): String? {
    return firstOrNull { it.autofillId == id }?.valueText?.trim()?.takeIf { it.isNotBlank() }
}

data class AutofillFieldSet(
    val usernameFields: List<AutofillId>,
    val passwordFields: List<AutofillId>,
    val cardNumberFields: List<AutofillId> = emptyList(),
    val cardExpiryFields: List<AutofillId> = emptyList(),
    val cardExpiryMonthFields: List<AutofillId> = emptyList(),
    val cardExpiryYearFields: List<AutofillId> = emptyList(),
    val cardCvvFields: List<AutofillId> = emptyList(),
    val cardNameFields: List<AutofillId> = emptyList(),
) {
    val canFill: Boolean = usernameFields.isNotEmpty() || passwordFields.isNotEmpty()

    /** A field anywhere in a payment group — the trigger for offering cards. */
    val isPaymentForm: Boolean = cardNumberFields.isNotEmpty() || cardExpiryFields.isNotEmpty() ||
            cardExpiryMonthFields.isNotEmpty() || cardExpiryYearFields.isNotEmpty() ||
            cardCvvFields.isNotEmpty()

    fun loginIds(): Array<AutofillId> = (usernameFields + passwordFields).distinct().toTypedArray()

    fun allIds(): Array<AutofillId> = (
            usernameFields + passwordFields + cardNumberFields + cardExpiryFields +
                    cardExpiryMonthFields + cardExpiryYearFields + cardCvvFields + cardNameFields
            ).distinct().toTypedArray()

    companion object {
        fun from(fields: List<ParsedAutofillField>): AutofillFieldSet {
            // First, filter to "autofillable" inputs only (extension: velaIsAutofillable)
            val autofillable = fields.filter { it.isAutofillable() }
            val usernames = mutableListOf<AutofillId>()
            val passwords = mutableListOf<AutofillId>()
            val numbers = mutableListOf<AutofillId>()
            val expiries = mutableListOf<AutofillId>()
            val expMonths = mutableListOf<AutofillId>()
            val expYears = mutableListOf<AutofillId>()
            val cvvs = mutableListOf<AutofillId>()
            val names = mutableListOf<AutofillId>()
            for (field in autofillable) {
                // A payment field is claimed before the login heuristics, so a
                // cardholder field is never mistaken for a username.
                when (field.cardFieldKind()) {
                    CardField.Number -> numbers += field.autofillId
                    CardField.Expiry -> expiries += field.autofillId
                    CardField.ExpMonth -> expMonths += field.autofillId
                    CardField.ExpYear -> expYears += field.autofillId
                    CardField.Cvv -> cvvs += field.autofillId
                    CardField.Name -> names += field.autofillId
                    null -> if (field.isUsernameField()) usernames += field.autofillId
                    else if (field.isPasswordField()) passwords += field.autofillId
                }
            }
            return AutofillFieldSet(
                usernameFields = usernames.distinct(),
                passwordFields = passwords.distinct(),
                cardNumberFields = numbers.distinct(),
                cardExpiryFields = expiries.distinct(),
                cardExpiryMonthFields = expMonths.distinct(),
                cardExpiryYearFields = expYears.distinct(),
                cardCvvFields = cvvs.distinct(),
                cardNameFields = names.distinct(),
            )
        }
    }
}

/** Which part of a payment group a field is, if any. */
internal enum class CardField { Number, Expiry, ExpMonth, ExpYear, Cvv, Name }

/**
 * The payment-field heuristics, deliberately narrow so an ordinary
 * "name"/"number" input is not claimed. Mirrors the browser extension's
 * `velaCardFieldKind`. CVV and the split expiry months/years are matched before
 * the generic number/expiry names, which would otherwise absorb them.
 *
 * Takes the raw signals rather than a [ParsedAutofillField] so it is testable on
 * the JVM (an `AutofillId` cannot be constructed off-device).
 */
internal fun cardFieldKindOf(
    htmlName: String?,
    htmlId: String?,
    autocomplete: String?,
    hint: String?,
    idEntry: String?,
): CardField? {
    val text = listOfNotNull(htmlName, htmlId, autocomplete, hint, idEntry)
        .joinToString(" ")
        .lowercase()
        .replace(Regex("[^a-z0-9]"), "")
    if (text.isEmpty()) return null
    fun has(vararg needles: String) = needles.any { text.contains(it) }

    if (has("cvv", "cvc", "csc", "cvn", "ccv", "cardcode", "securitycode", "cardverif", "cryptogramme")) {
        return CardField.Cvv
    }
    if (has("ccexpmonth", "cardexpmonth", "expmonth", "expirymonth", "expmo", "cardmonth", "ccmm", "cbdatemois")) {
        return CardField.ExpMonth
    }
    if (has("ccexpyear", "cardexpyear", "expyear", "expiryyear", "expyy", "cardyear", "ccyy", "cbdateann")) {
        return CardField.ExpYear
    }
    if (has("ccnumber", "cardnumber", "creditcard", "ccnum", "cardnum", "ccno", "cardno",
            "numerocarte", "numcarte", "cbnum", "cardpan")) {
        return CardField.Number
    }
    if (has("ccexp", "cardexp", "ccxp", "expirationdate", "expirydate", "cardexpiry",
            "cardexpiration", "paymentcardexpiration", "validite", "dateexpiration")) {
        return CardField.Expiry
    }
    if (has("cardholder", "ccname", "cardname", "nameoncard")) {
        return CardField.Name
    }
    return null
}

private fun ParsedAutofillField.cardFieldKind(): CardField? =
    cardFieldKindOf(htmlName, htmlId, effectiveAutocomplete, androidHint, idEntry)

/**
 * Extension equivalent of `velaIsAutofillable(el)`.
 * Only considers nodes that look like text/password inputs.
 */
private fun ParsedAutofillField.isAutofillable(): Boolean {
    val htmlType = this.htmlType?.lowercase().orEmpty()

    // Allowed HTML types (extension: password, text, email, tel, url)
    if (htmlType == "password" || htmlType == "text" || htmlType == "email" || htmlType == "tel" || htmlType == "url") {
        return true
    }

    // If no HTML type is available, fall back to Android input-type heuristics
    val variation = inputType and InputType.TYPE_MASK_VARIATION
    val isPasswordLike = variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
            variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD

    val isTextLike = variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
            variation == InputType.TYPE_TEXT_VARIATION_URI ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS

    return isPasswordLike || isTextLike || htmlType.isEmpty()
}

/**
 * Extension equivalent of password-field detection.
 * Strong signals first, then fallbacks.
 */
private fun ParsedAutofillField.isPasswordField(): Boolean {
    // Strong signal 1: autocomplete contains "password"
    val auto = effectiveAutocomplete?.lowercase().orEmpty()
    if (auto.contains("password") || auto == "current-password" || auto == "new-password") return true

    // Strong signal 2: HTML type is password
    val type = htmlType?.lowercase().orEmpty()
    if (type == "password") return true

    // Strong signal 3: Android input type is password
    val variation = inputType and InputType.TYPE_MASK_VARIATION
    if (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
        variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
        variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
        variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
    ) {
        return true
    }

    // Fallback: fuzzy keyword search (same patterns as extension)
    return searchableText().any { text ->
        PASSWORD_KEYWORDS.any { keyword -> text.contains(keyword) }
    }
}

/**
 * Extension equivalent of username-field detection.
 * Must NOT be a password field, then checked for strong signals + fuzzy match.
 */
private fun ParsedAutofillField.isUsernameField(): Boolean {
    if (isPasswordField()) return false

    // Strong signal 1: autocomplete is username / email / login / user
    val auto = effectiveAutocomplete?.lowercase().orEmpty()
    if (auto == "username" || auto == "email" || auto == "login" || auto == "user") return true

    // Strong signal 2: HTML type is email or tel
    val type = htmlType?.lowercase().orEmpty()
    if (type == "email" || type == "tel") return true

    // Strong signal 3: Android input type is email
    val variation = inputType and InputType.TYPE_MASK_VARIATION
    if (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
        variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
    ) {
        return true
    }

    // Fallback: fuzzy match against extension's UsernameFieldNames
    val criteriaList = fuzzyCriteria().map { normalizeForFuzzy(it) }
    val options = USERNAME_FIELD_NAMES.map { normalizeForFuzzy(it) }

    for (criteria in criteriaList) {
        if (criteria.isBlank()) continue
        for (option in options) {
            if (fuzzyMatch(criteria, option)) return true
        }
    }

    return false
}

/**
 * Collects every text token we can search for keywords (mirrors extension's
 * `searchableText()` which joins name, id, placeholder, aria-label, title).
 * On Android we map placeholder/hint to the framework's `hint` property.
 */
private fun ParsedAutofillField.searchableText(): List<String> {
    return listOfNotNull(htmlName, htmlId, androidHint, idEntry)
        .map { it.lowercase().replace("-", "_").replace("[", "_").replace("]", "_") }
}
