package com.vela.android.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
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
import com.vela.android.core.VaultItem
import com.vela.android.core.VaultMeta
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
    onBack: () -> Unit
) {
    val activity = LocalContext.current as? MainActivity
    val initialType = when (editItem) {
        is VaultItem.CreditCard -> "card"
        is VaultItem.SecureNote -> "note"
        else -> "login"
    }
    var selectedType by remember(editItem?.id) { mutableStateOf(initialType) }
    var name by remember(editItem?.id) { mutableStateOf(editItem?.name.orEmpty()) }
    var url by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Login)?.url.orEmpty()) }
    var username by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Login)?.username.orEmpty()) }
    var password by remember(editItem?.id) { mutableStateOf((editItem as? VaultItem.Login)?.password.orEmpty()) }
    var passwordLength by remember { mutableStateOf("20") }
    var includeUppercase by remember { mutableStateOf(true) }
    var includeNumbers by remember { mutableStateOf(true) }
    var includeSymbols by remember { mutableStateOf(true) }
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

    val types = listOf(
        "login" to Icons.Filled.Key,
        "card" to Icons.Filled.CreditCard,
        "note" to Icons.Filled.Description
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VelaColors.SurfaceBase)
    ) {
        VelaTopBar(title = if (editItem == null) "Add Item" else "Edit Item", onBack = onBack)

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
        ) {
            Spacer(Modifier.height(16.dp))

            Text("Type", color = VelaColors.TextMuted, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 2.sp)
            Spacer(Modifier.height(10.dp))

            if (editItem == null) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    types.forEach { (type, icon) ->
                        val selected = selectedType == type
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .background(
                                    if (selected) VelaColors.Green.copy(alpha = 0.12f) else VelaColors.SurfaceLow,
                                    shape = RoundedCornerShape(14.dp)
                                )
                                .clickable { selectedType = type }
                                .padding(12.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Icon(
                                icon, type,
                                modifier = Modifier.size(24.dp),
                                tint = if (selected) VelaColors.Green else VelaColors.TextSecondary
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                type.replaceFirstChar { it.uppercase() },
                                fontSize = 11.sp,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                color = if (selected) VelaColors.Green else VelaColors.TextSecondary
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(24.dp))

            when (selectedType) {
                "login" -> {
                    VelaTextField(value = name, onValueChange = { name = it }, label = "Name")
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = url, onValueChange = { url = it }, label = "URL")
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = username, onValueChange = { username = it }, label = "Username")
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = password, onValueChange = { password = it }, label = "Password", isPassword = true)
                    Spacer(Modifier.height(12.dp))
                    VelaCard {
                        Text("Password Generator", color = VelaColors.TextMuted, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 1.5.sp)
                        Spacer(Modifier.height(12.dp))
                        VelaTextField(
                            value = passwordLength,
                            onValueChange = { passwordLength = it.filter(Char::isDigit).take(2) },
                            label = "Length",
                            keyboardType = KeyboardType.Number
                        )
                        Spacer(Modifier.height(8.dp))
                        GeneratorOption("Uppercase", includeUppercase) { includeUppercase = it }
                        GeneratorOption("Numbers", includeNumbers) { includeNumbers = it }
                        GeneratorOption("Symbols", includeSymbols) { includeSymbols = it }
                    }
                    Spacer(Modifier.height(10.dp))
                    VelaButton(
                        text = "Generate Password",
                        onClick = {
                            password = generatePassword(
                                length = passwordLength.toIntOrNull()?.coerceIn(8, 64) ?: 20,
                                uppercase = includeUppercase,
                                numbers = includeNumbers,
                                symbols = includeSymbols
                            )
                        },
                        style = VelaButtonStyle.Surface
                    )
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = totp, onValueChange = { totp = it }, label = "TOTP Secret", placeholder = "Base32 secret or otpauth:// URL")
                    Spacer(Modifier.height(10.dp))
                    VelaButton(
                        text = "Scan TOTP QR",
                        onClick = {
                            if (activity == null) {
                                totpScanMessage = "Unable to open QR scanner"
                            } else {
                                activity.launchQrScanner("Scan TOTP QR code") { contents ->
                                    when {
                                        contents.isNullOrEmpty() -> totpScanMessage = "Scan cancelled"
                                        isSupportedTotpQr(contents) -> {
                                            totp = contents
                                            totpScanMessage = "TOTP QR scanned"
                                        }
                                        else -> totpScanMessage = "Unsupported QR code"
                                    }
                                }
                            }
                        },
                        style = VelaButtonStyle.Surface,
                        icon = Icons.Filled.QrCodeScanner
                    )
                    totpScanMessage?.let {
                        Spacer(Modifier.height(8.dp))
                        Text(it, color = VelaColors.TextMuted, fontSize = 12.sp)
                    }
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = notes, onValueChange = { notes = it }, label = "Notes", singleLine = false)
                }
                "card" -> {
                    VelaTextField(value = cardholder, onValueChange = { cardholder = it }, label = "Cardholder Name")
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = cardNumber, onValueChange = { cardNumber = it }, label = "Card Number", isMono = true)
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = expiration, onValueChange = { expiration = it }, label = "Expiry (MM/YY)")
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = cvv, onValueChange = { cvv = it }, label = "CVV", isPassword = true)
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = pin, onValueChange = { pin = it }, label = "PIN", isPassword = true)
                }
                "note" -> {
                    VelaTextField(value = name, onValueChange = { name = it }, label = "Title")
                    Spacer(Modifier.height(14.dp))
                    VelaTextField(value = notes, onValueChange = { notes = it }, label = "Notes", singleLine = false)
                }
            }

            Spacer(Modifier.height(24.dp))

            VelaButton(
                text = "Save",
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
                            totp = totp.ifBlank { null }
                        )
                        "card" -> VaultItem.CreditCard(
                            meta = VaultMeta(
                                id = editItem?.id ?: UUID.randomUUID().toString(),
                                name = cardholder.ifBlank { "Card" },
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
                        else -> VaultItem.Login(
                            meta = VaultMeta(
                                id = UUID.randomUUID().toString(),
                                name = name.ifBlank { "Untitled" },
                                favorite = false
                            ),
                            url = url,
                            username = username,
                            password = password
                        )
                    }
                    onSave(item)
                },
                style = VelaButtonStyle.Gradient,
                enabled = when (selectedType) {
                    "login" -> username.isNotBlank() || password.isNotBlank() || name.isNotBlank()
                    "card" -> cardNumber.isNotBlank()
                    "note" -> notes.isNotBlank() || name.isNotBlank()
                    else -> true
                }
            )

            Spacer(Modifier.height(32.dp))
        }
    }
}

private fun isSupportedTotpQr(contents: String): Boolean {
    if (contents.startsWith("otpauth://", ignoreCase = true)) return true
    return contents.matches(Regex("^[A-Z2-7=\\s-]{16,}$", RegexOption.IGNORE_CASE))
}

@Composable
private fun GeneratorOption(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = checked, onCheckedChange = onCheckedChange)
        Text(label, color = VelaColors.TextPrimary, fontSize = 14.sp)
    }
}

private fun generatePassword(
    length: Int = 20,
    uppercase: Boolean = true,
    numbers: Boolean = true,
    symbols: Boolean = true
): String {
    val lower = "abcdefghijkmnopqrstuvwxyz"
    val upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    val digits = "23456789"
    val symbolChars = "!@#$%^&*"
    val alphabet = buildString {
        append(lower)
        if (uppercase) append(upper)
        if (numbers) append(digits)
        if (symbols) append(symbolChars)
    }.ifBlank { lower }
    val random = SecureRandom()
    return buildString {
        repeat(length) {
            append(alphabet[random.nextInt(alphabet.length)])
        }
    }
}
