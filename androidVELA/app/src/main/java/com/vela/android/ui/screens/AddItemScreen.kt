package com.vela.android.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.MainActivity
import com.vela.android.core.*
import com.vela.android.core.VaultItem
import com.vela.android.core.VaultMeta
import com.vela.android.ui.components.*
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.components.VelaTextField
import com.vela.android.ui.components.VelaTopBar
import com.vela.android.ui.theme.VelaColors
import java.security.SecureRandom
import java.time.Instant
import java.util.UUID

@Composable
fun AddItemScreen(
    editItem: VaultItem? = null,
    onSave: (VaultItem) -> Unit,
    onBack: () -> Unit,
    initialPassword: String = "",
    readOnly: Boolean = com.vela.android.core.VelaRepositories.vault.richerVaultReadOnly,
    organization: VaultOrganization = VelaRepositories.vault.organization.value
) {
    val activity = LocalContext.current as? MainActivity
    val initialType = when (editItem) {
        is VaultItem.CreditCard -> "card"
        is VaultItem.SecureNote -> "note"
        is VaultItem.Identity -> "identity"
        is VaultItem.Passkey -> "passkey"
        is VaultItem.FileBlob -> "file"
        is VaultItem.BreachMonitor -> "breach"
        else -> "login"
    }
    var richData by remember(editItem?.id) { mutableStateOf(editItem?.rich ?: RichData()) }
    var firstName by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Identity)?.firstName.orEmpty()) }
    var lastName by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Identity)?.lastName.orEmpty()) }
    var ssn by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Identity)?.ssn.orEmpty()) }
    var saveError by remember { mutableStateOf<String?>(null) }
    var selectedType by remember(editItem?.id) { mutableStateOf(initialType) }
    var name by remember(editItem?.id) { mutableStateOf(editItem?.name.orEmpty()) }
    var url by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Login)?.url.orEmpty()) }
    var username by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Login)?.username.orEmpty()) }
    var password by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Login)?.password ?: initialPassword) }
    var totp by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Login)?.totp.orEmpty()) }
    var notes by remember(editItem?.id) {
        mutableStateOf(
            when (editItem) {
                is VaultItem.Login -> editItem.notes.orEmpty()
                is VaultItem.SecureNote -> editItem.content
                is VaultItem.CreditCard -> editItem.notes.orEmpty()
                else -> ""
            }
        )
    }
    var cardNumber by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.CreditCard)?.cardNumber.orEmpty()) }
    var cardholder by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.CreditCard)?.cardholderName.orEmpty()) }
    var expiration by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.CreditCard)?.expiration.orEmpty()) }
    var cvv by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.CreditCard)?.cvv.orEmpty()) }
    var pin by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.CreditCard)?.pin.orEmpty()) }
    var totpScanMessage by remember(editItem?.id) { mutableStateOf<String?>(null) }

    var advanced by remember { mutableStateOf(false) }
    var generatorOpen by remember { mutableStateOf(false) }
    Box(Modifier.fillMaxSize()) {
        InstrumentSheet(true, if (editItem == null) "Something worth keeping." else "Edit item", onBack) {
            if (editItem == null) ChipRow(listOf("Login", "Card", "Note", "Identity"), selectedType.replaceFirstChar { it.uppercase() },
                { selectedType = it.lowercase() })
            SheetInput("Name", name, { name = it }, "Give it a name")
            when (selectedType) {
                "login" -> {
                    SheetInput("Username", username, { username = it }, "name@example.test", keyboard = KeyboardType.Email)
                    SheetInput("Password", password, { password = it }, "A strong password", secret = true)
                    InstrumentPill("Generate password", { generatorOpen = true },
                        Modifier.padding(top = 10.dp), icon = InstrumentIcons.Dice)
                    SheetInput("Website", url, { url = it }, "https://example.test", keyboard = KeyboardType.Uri)
                    InstrumentPill(if (advanced) "Fewer options" else "Authenticator & notes", { advanced = !advanced }, Modifier.padding(top = 16.dp))
                    if (advanced || totp.isNotBlank() || notes.isNotBlank()) {
                        SheetInput("TOTP secret", totp, { totp = it }, "Base32 secret or otpauth:// URL", secret = true)
                        InstrumentPill("Scan TOTP QR", {
                            if (activity == null) totpScanMessage = "QR scanning is available in the main app."
                            else activity.launchQrScanner("Scan TOTP QR code") { contents ->
                                when {
                                    contents.isNullOrEmpty() -> totpScanMessage = "Scan cancelled"
                                    isSupportedTotpQr(contents) -> { totp = contents; totpScanMessage = "TOTP QR scanned" }
                                    else -> totpScanMessage = "Unsupported QR code"
                                }
                            }
                        }, Modifier.padding(top = 10.dp), icon = InstrumentIcons.Grid)
                        totpScanMessage?.let { InstrumentFine(it) }
                        SheetInput("Notes", notes, { notes = it }, "Only you can read these.", multiline = true)
                    }
                }
                "card" -> {
                    SheetInput("Cardholder", cardholder, { cardholder = it }, "Name on the card")
                    SheetInput("Card number", cardNumber, { cardNumber = it }, "0000 0000 0000 0000", mono = true, keyboard = KeyboardType.Number)
                    SheetInput("Expires", expiration, { expiration = it }, "MM/YY")
                    SheetInput("CVV", cvv, { cvv = it }, secret = true, keyboard = KeyboardType.Number)
                    SheetInput("PIN", pin, { pin = it }, secret = true, keyboard = KeyboardType.Number)
                    SheetInput("Notes", notes, { notes = it }, multiline = true)
                }
                "identity" -> {
                    SheetInput("First name", firstName, { firstName = it })
                    SheetInput("Last name", lastName, { lastName = it })
                    SheetInput("Identity number", ssn, { ssn = it }, secret = true)
                    SheetInput("Notes", notes, { notes = it }, multiline = true)
                }
                "note" -> SheetInput("Notes", notes, { notes = it }, "Write anything. It stays encrypted.", multiline = true)
            }
            RichItemEditor(richData, organization, selectedType) { richData = it }
            saveError?.let { androidx.compose.material3.Text(it, color = VelaColors.ErrorRed) }
            Spacer(Modifier.height(24.dp))
            VelaButton(
                text = if (readOnly) "Read-only: edit on desktop" else if (editItem == null) "Add to vault" else "Save changes",
                onClick = {
                    val item = when (selectedType) {
                        "login" -> VaultItem.Login(
                            meta = VaultMeta(
                                id = editItem?.id ?: UUID.randomUUID().toString(),
                                name = name.ifBlank { "Untitled" },
                                notes = notes.ifBlank { null },
                                createdAt = editItem?.createdAt ?: Instant.now(),
                                updatedAt = Instant.now(),
                                lastModifiedDevice = editItem?.lastModifiedDevice,
                                favorite = editItem?.favorite ?: false,
                                shared = editItem?.shared ?: false,
                                shareRecipient = editItem?.shareRecipient
                            ),
                            url = url,
                            username = username,
                            password = password,
                            totp = totp.ifBlank { null },
                            appIds = (editItem as? VaultItem.Login)?.appIds.orEmpty()
                        )
                        "card" -> VaultItem.CreditCard(
                            meta = VaultMeta(
                                id = editItem?.id ?: UUID.randomUUID().toString(),
                                name = name.ifBlank { cardholder.ifBlank { "Card" } },
                                notes = notes.ifBlank { null },
                                createdAt = editItem?.createdAt ?: Instant.now(),
                                updatedAt = Instant.now(),
                                lastModifiedDevice = editItem?.lastModifiedDevice,
                                favorite = editItem?.favorite ?: false,
                                shared = editItem?.shared ?: false,
                                shareRecipient = editItem?.shareRecipient
                            ),
                            cardholderName = cardholder,
                            cardNumber = cardNumber,
                            expiration = expiration,
                            cvv = cvv,
                            pin = pin.ifBlank { null }
                        )
                        "note" -> VaultItem.SecureNote(
                            meta = VaultMeta(
                                id = editItem?.id ?: UUID.randomUUID().toString(),
                                name = name.ifBlank { "Note" },
                                notes = null,
                                createdAt = editItem?.createdAt ?: Instant.now(),
                                updatedAt = Instant.now(),
                                lastModifiedDevice = editItem?.lastModifiedDevice,
                                favorite = editItem?.favorite ?: false,
                                shared = editItem?.shared ?: false,
                                shareRecipient = editItem?.shareRecipient
                            ),
                            content = notes
                        )
                        "identity" -> VaultItem.Identity(
                            meta = editItem?.meta?.copy(name = name.ifBlank { "Identity" }, notes = notes.ifBlank { null }, updatedAt = Instant.now())
                                ?: VaultMeta(name = name.ifBlank { "Identity" }, notes = notes.ifBlank { null }),
                            firstName = firstName, lastName = lastName, ssn = ssn
                        )
                        else -> editItem?.withMeta { it.copy(name = name, notes = notes.ifBlank { null }, updatedAt = Instant.now()) }
                            ?: error("Unsupported item type")
                    }
                    try {
                        if (organization.enabled) organization.validate(richData, editItem?.rich ?: RichData())
                        onSave(item.withRich(richData))
                    } catch (e: Exception) { saveError = e.message ?: "Could not save item" }
                },
                style = VelaButtonStyle.Gradient,
                enabled = !readOnly && when (selectedType) {
                    "login" -> username.isNotBlank() || password.isNotBlank() || name.isNotBlank()
                    "card" -> cardNumber.isNotBlank()
                    "note" -> notes.isNotBlank() || name.isNotBlank()
                    else -> true
                }
            )

            Spacer(Modifier.height(32.dp))
        }
        if (generatorOpen) InstrumentSheet(true, "Generate a password", { generatorOpen = false }) {
            GeneratorScreen(onSaveLogin = { generated -> password = generated; generatorOpen = false },
                embedded = true, useLabel = "Use this password")
        }
    }
}

private fun isSupportedTotpQr(contents: String): Boolean {
    if (contents.startsWith("otpauth://", ignoreCase = true)) return true
    return contents.matches(Regex("^[A-Z2-7=\\s-]{16,}$", RegexOption.IGNORE_CASE))
}
