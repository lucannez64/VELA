package com.vela.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.theme.VelaColors

@Composable
fun VelaTextField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    label: String? = null,
    placeholder: String? = null,
    isPassword: Boolean = false,
    isMono: Boolean = false,
    keyboardType: KeyboardType = KeyboardType.Text,
    singleLine: Boolean = true,
    trailingIcon: @Composable (() -> Unit)? = null,
    enabled: Boolean = true
) {
    var passwordVisible by remember { mutableStateOf(false) }
    var isFocused by remember { mutableStateOf(false) }

    val textStyle = if (isMono) {
        TextStyle.Default.copy(fontSize = 14.sp)
    } else {
        TextStyle.Default
    }

    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier
            .fillMaxWidth()
            .onFocusChanged { isFocused = it.isFocused },
        label = label?.let { { Text(it, fontSize = 13.sp) } },
        placeholder = placeholder?.let { { Text(it, color = VelaColors.TextMuted) } },
        textStyle = textStyle,
        singleLine = singleLine,
        enabled = enabled,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        visualTransformation = if (isPassword && !passwordVisible)
            PasswordVisualTransformation() else VisualTransformation.None,
        trailingIcon = {
            if (isPassword) {
                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                    Icon(
                        if (passwordVisible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        null,
                        modifier = Modifier.size(20.dp),
                        tint = VelaColors.TextMuted
                    )
                }
            } else {
                trailingIcon?.invoke()
            }
        },
        shape = RoundedCornerShape(14.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedTextColor = VelaColors.TextPrimary,
            unfocusedTextColor = VelaColors.TextPrimary,
            disabledTextColor = VelaColors.TextMuted,
            focusedBorderColor = if (isFocused) VelaColors.Green.copy(alpha = 0.4f) else VelaColors.Outline.copy(alpha = 0.15f),
            unfocusedBorderColor = VelaColors.Outline.copy(alpha = 0.15f),
            focusedContainerColor = VelaColors.SurfaceHighest,
            unfocusedContainerColor = VelaColors.SurfaceHighest,
            disabledContainerColor = VelaColors.SurfaceHigh,
            cursorColor = VelaColors.Green,
            focusedLabelColor = VelaColors.Green,
            unfocusedLabelColor = VelaColors.TextMuted,
            focusedPlaceholderColor = VelaColors.TextMuted.copy(alpha = 0.5f),
            unfocusedPlaceholderColor = VelaColors.TextMuted.copy(alpha = 0.3f)
        )
    )
}

@Composable
fun VelaSearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = "Search vault"
) {
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChange,
        modifier = modifier.fillMaxWidth(),
        textStyle = TextStyle(fontSize = 16.sp, color = VelaColors.TextPrimary),
        singleLine = true,
        placeholder = { Text(placeholder, color = VelaColors.TextMuted.copy(alpha = 0.5f)) },
        leadingIcon = {
            Icon(
                Icons.Filled.Search,
                null,
                modifier = Modifier.size(22.dp),
                tint = if (query.isNotEmpty()) VelaColors.Green else VelaColors.TextMuted
            )
        },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQueryChange("") }) {
                    Icon(Icons.Filled.Close, null, modifier = Modifier.size(18.dp), tint = VelaColors.TextMuted)
                }
            }
        },
        shape = RoundedCornerShape(16.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedTextColor = VelaColors.TextPrimary,
            unfocusedTextColor = VelaColors.TextPrimary,
            focusedBorderColor = VelaColors.Green.copy(alpha = 0.35f),
            unfocusedBorderColor = VelaColors.SurfaceHighest,
            focusedContainerColor = VelaColors.SurfaceDarkest,
            unfocusedContainerColor = VelaColors.SurfaceDarkest,
            cursorColor = VelaColors.Green
        )
    )
}
