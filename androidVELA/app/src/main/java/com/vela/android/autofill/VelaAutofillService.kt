package com.vela.android.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
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

            if (!fillable.canFill) {
                Log.d(TAG, "onFillRequest: nothing fillable")
                callback.onSuccess(null)
                return
            }

            if (!VelaRepositories.security.session.value.unlocked) {
                Log.d(TAG, "onFillRequest: vault locked, showing unlock prompt")
                callback.onSuccess(buildLockedResponse(fillable.allIds()))
                return
            }

            val domain = fields.firstNotNullOfOrNull { it.webDomain }
                ?: structure.activityComponent?.packageName
            val candidates = VelaRepositories.vault.findAutofillLogins(domain, structure.activityComponent?.packageName)
            Log.d(TAG, "onFillRequest: domain=$domain candidates=${candidates.size}")
            candidates.firstOrNull()?.let {
                Log.d(TAG, "onFillRequest: first candidate name=${it.name} url=${it.url} user=${it.username.isNotBlank()} pass=${it.password.isNotBlank()}")
            }

            val responseBuilder = FillResponse.Builder()
                .setSaveInfo(buildSaveInfo(fillable))
            var added = 0
            candidates.take(MAX_DATASETS).forEachIndexed { index, login ->
                Log.d(TAG, "onFillRequest: building dataset $index for ${login.name}")
                val dataset = buildLoginDataset(fillable, login)
                if (dataset != null) {
                    responseBuilder.addDataset(dataset)
                    added++
                }
            }
            val response = responseBuilder.build()
            Log.d(TAG, "onFillRequest: sending response with $added/${candidates.size.coerceAtMost(MAX_DATASETS)} datasets")
            callback.onSuccess(response)
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

            val domain = fields.firstNotNullOfOrNull { it.webDomain }
            val packageName = structure.activityComponent?.packageName
            val target = domain?.takeIf { it.isNotBlank() } ?: packageName.orEmpty()
            if (target.isBlank()) {
                callback.onFailure("No app or website target found")
                return
            }

            val existing = VelaRepositories.vault
                .findAutofillLogins(domain, packageName)
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
                        password = password
                    )
                )
                Log.d(TAG, "Saved new Autofill login for $target")
            } else if (existing.password != password) {
                VelaRepositories.vault.updateItem(
                    existing.copy(
                        password = password,
                        meta = existing.meta.copy(
                            updatedAt = now,
                            lastModifiedDevice = "android-local"
                        )
                    )
                )
                Log.d(TAG, "Updated Autofill login for $target")
            } else {
                Log.d(TAG, "Autofill save ignored unchanged login for $target")
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

    private fun buildLoginDataset(fields: AutofillFieldSet, login: VaultItem.Login): Dataset? {
        return try {
            val presentation = datasetPresentation(login.name, login.username)
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
            Log.e(TAG, "buildLoginDataset failed for ${login.name}", e)
            null
        }
    }

    private fun buildLockedResponse(ids: Array<AutofillId>): FillResponse {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(MainActivity.EXTRA_AUTOFILL_UNLOCK, true)
        val pendingIntent = PendingIntent.getActivity(
            this,
            1001,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val presentation = datasetPresentation("Unlock VELA", "Open vault to fill passwords")
        val builder = FillResponse.Builder()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            builder.setAuthentication(ids, pendingIntent.intentSender, presentations(presentation))
        } else {
            @Suppress("DEPRECATION")
            builder.setAuthentication(ids, pendingIntent.intentSender, presentation)
        }
        return builder.build()
    }

    private fun buildSaveInfo(fields: AutofillFieldSet): SaveInfo {
        return SaveInfo.Builder(
            SaveInfo.SAVE_DATA_TYPE_PASSWORD,
            fields.allIds()
        )
            .setDescription("Save login in VELA")
            .build()
    }

    private fun datasetPresentation(title: String, subtitle: String?): RemoteViews {
        return RemoteViews(packageName, R.layout.autofill_dataset).apply {
            setTextViewText(R.id.title, title)
            setTextViewText(R.id.subtitle, subtitle ?: getString(R.string.autofill_service_label))
        }
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

    @android.annotation.TargetApi(Build.VERSION_CODES.TIRAMISU)
    private fun presentations(presentation: RemoteViews): Presentations {
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

private fun List<ParsedAutofillField>.valueFor(id: AutofillId): String? {
    return firstOrNull { it.autofillId == id }?.valueText?.trim()?.takeIf { it.isNotBlank() }
}

data class AutofillFieldSet(
    val usernameFields: List<AutofillId>,
    val passwordFields: List<AutofillId>
) {
    val canFill: Boolean = usernameFields.isNotEmpty() || passwordFields.isNotEmpty()

    fun allIds(): Array<AutofillId> = (usernameFields + passwordFields).distinct().toTypedArray()

    companion object {
        fun from(fields: List<ParsedAutofillField>): AutofillFieldSet {
            // First, filter to "autofillable" inputs only (extension: velaIsAutofillable)
            val autofillable = fields.filter { it.isAutofillable() }
            return AutofillFieldSet(
                usernameFields = autofillable.filter { it.isUsernameField() }.map { it.autofillId }.distinct(),
                passwordFields = autofillable.filter { it.isPasswordField() }.map { it.autofillId }.distinct()
            )
        }
    }
}

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
