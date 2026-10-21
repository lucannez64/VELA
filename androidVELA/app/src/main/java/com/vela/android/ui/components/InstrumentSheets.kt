package com.vela.android.ui.components

import androidx.compose.foundation.border
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.theme.InstrumentBody
import com.vela.android.ui.theme.InstrumentMono
import com.vela.android.ui.theme.VelaColors

/** Sheet text input: 48dp, panel fill, hairline that turns violet on focus. */
@Composable
fun SheetInput(label: String, value: String, onValueChange: (String) -> Unit, placeholder: String = "",
    secret: Boolean = false, mono: Boolean = false, multiline: Boolean = false, keyboard: KeyboardType = KeyboardType.Text) {
    var focused by remember { mutableStateOf(false) }
    var shown by remember { mutableStateOf(false) }
    SheetLabel(label)
    val shape = RoundedCornerShape(14.dp)
    Row(
        Modifier.fillMaxWidth().heightIn(min = if (multiline) 85.dp else 48.dp).background(Ink.panel, shape)
            .border(1.dp, if (focused) VelaColors.Violet else Ink.line2, shape).padding(start = 12.dp, end = 4.dp),
        verticalAlignment = if (multiline) Alignment.Top else Alignment.CenterVertically,
    ) {
        Box(Modifier.weight(1f).padding(vertical = 12.dp)) {
            if (value.isEmpty()) Text(placeholder, fontSize = 12.sp, color = Ink.faint)
            BasicTextField(
                value, onValueChange, Modifier.fillMaxWidth().onFocusChanged { focused = it.isFocused }.semantics { contentDescription = label },
                singleLine = !multiline,
                textStyle = TextStyle(fontSize = 12.sp, color = VelaColors.TextPrimary, fontFamily = if (mono || secret) InstrumentMono else InstrumentBody),
                visualTransformation = if (secret && !shown) PasswordVisualTransformation('•') else VisualTransformation.None,
                keyboardOptions = KeyboardOptions(keyboardType = if (secret && keyboard == KeyboardType.Number) KeyboardType.NumberPassword else if (secret) KeyboardType.Password else keyboard),
                cursorBrush = SolidColor(VelaColors.Violet),
            )
        }
        if (secret) InstrumentIconButton(if (shown) InstrumentIcons.Eyeoff else InstrumentIcons.Eye,
            if (shown) "Hide $label" else "Show $label", { shown = !shown }, size = 40.dp, bordered = false, tint = VelaColors.TextMuted)
    }
}

@Composable
fun ChipRow(options: List<String>, selected: String, onSelect: (String) -> Unit, modifier: Modifier = Modifier) {
    Row(modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        options.forEach { InstrumentChip(it, it == selected, { onSelect(it) }) }
    }
}

data class ShareDraft(val toUser: Boolean, val recipient: String, val access: String, val expiry: String, val passphrase: Boolean, val once: Boolean)

/** Share one item: to a VELA user, or as an expiring link. */
@Composable
fun ShareItemSheet(visible: Boolean, itemName: String, onDismiss: () -> Unit,
    directOnly: Boolean = false, busy: Boolean = false, error: String? = null,
    onShare: (ShareDraft) -> Unit) {
    var toUser by remember(visible) { mutableStateOf(true) }
    var recipient by remember(visible) { mutableStateOf("") }
    var access by remember(visible) { mutableStateOf("View only") }
    var expiry by remember(visible) { mutableStateOf("1 day") }
    var passphrase by remember(visible) { mutableStateOf(true) }
    var once by remember(visible) { mutableStateOf(false) }
    InstrumentSheet(visible, "Share $itemName", onDismiss) {
        if (!directOnly) ChipRow(listOf("VELA user", "Share link"), if (toUser) "VELA user" else "Share link", { toUser = it == "VELA user" })
        if (toUser) {
            SheetInput(if (directOnly) "Recipient user ID" else "Recipient email", recipient, { recipient = it }, if (directOnly) "VELA user ID" else "name@example.com", keyboard = if (directOnly) KeyboardType.Text else KeyboardType.Email)
            if (!directOnly) {
                SheetLabel("Access")
                ChipRow(listOf("View only", "Can edit"), access, { access = it })
            }
            InstrumentFine("They'll get an encrypted copy. You can revoke access at any time.", Modifier.padding(top = 12.dp))
        } else {
            SheetLabel("Expires after")
            ChipRow(listOf("1 hour", "1 day", "7 days"), expiry, { expiry = it })
            Spacer(Modifier.height(14.dp))
            InstrumentGroup {
                InstrumentControlRow("Require a passphrase") { InstrumentToggle(passphrase, { passphrase = it }, "Require a passphrase") }
                GroupDivider()
                InstrumentControlRow("Delete after the first view") { InstrumentToggle(once, { once = it }, "Delete after the first view") }
            }
            InstrumentFine("Anyone with the link can open it until it expires or you revoke it.")
        }
        error?.let { androidx.compose.material3.Text(it, color = Ink.red) }
        InstrumentPill(if (busy) "Sending…" else if (toUser) "Send securely" else "Create link", { onShare(ShareDraft(toUser, recipient, access, expiry, passphrase, once)) },
            Modifier.fillMaxWidth().padding(top = 20.dp), icon = if (toUser) InstrumentIcons.Mail else InstrumentIcons.Link,
            style = PillStyle.Primary, enabled = !busy && (!toUser || if (directOnly) recipient.isNotBlank() else recipient.contains('@')))
    }
}

/** A short list of choices in a sheet (auto-lock, clipboard...). */
@Composable
fun ChoiceSheet(visible: Boolean, title: String, options: List<String>, selected: String, onDismiss: () -> Unit, onSelect: (String) -> Unit) {
    InstrumentSheet(visible, title, onDismiss) {
        InstrumentGroup {
            options.forEachIndexed { i, option ->
                if (i > 0) GroupDivider()
                Row(Modifier.fillMaxWidth().heightIn(min = 55.dp).instrumentClick { onSelect(option) }.padding(horizontal = 15.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Text(option, Modifier.weight(1f), fontSize = 12.sp, color = VelaColors.TextPrimary)
                    if (option == selected) InstrumentIcon(InstrumentIcons.Check, 17.dp, VelaColors.Violet)
                }
            }
        }
    }
}
