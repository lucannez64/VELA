package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Inbox
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.SearchOff
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.vela.android.core.ShareDirection
import com.vela.android.core.VaultItem
import com.vela.android.core.VaultShare
import com.vela.android.core.VelaRepositories
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.components.VelaSearchField
import com.vela.android.ui.components.VelaTextField
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun SharingScreen(items: List<VaultItem>, onBack: () -> Unit, preselectedItemId: String? = null) {
    val scope = rememberCoroutineScope()
    var shares by remember { mutableStateOf<List<VaultShare>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var sentTab by remember { mutableStateOf(false) }

    val shareableItems = items.filter { !it.shared }
    var selectedItem by remember { mutableStateOf<VaultItem?>(null) }
    var showPicker by remember { mutableStateOf(false) }

    var recipient by remember { mutableStateOf("") }

    // Auto-select preselected item
    LaunchedEffect(preselectedItemId, shareableItems) {
        if (preselectedItemId != null && selectedItem == null) {
            selectedItem = shareableItems.find { it.id == preselectedItemId }
        }
    }

    fun load() {
        error = null
        scope.launch(Dispatchers.IO) {
            runCatching { VelaRepositories.sharing.listShares() }
                .onSuccess { result -> withContext(Dispatchers.Main) { shares = result } }
                .onFailure { e -> withContext(Dispatchers.Main) { error = e.message ?: "Failed to load shares" } }
        }
    }

    LaunchedEffect(Unit) { load() }

    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).padding(20.dp)) {
        ScreenHeader("Sharing", onBack)
        Spacer(Modifier.height(14.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            VelaButton("Received", { sentTab = false }, style = if (!sentTab) VelaButtonStyle.Tonal else VelaButtonStyle.Surface, icon = Icons.Filled.Inbox, fullWidth = false)
            VelaButton("Sent", { sentTab = true }, style = if (sentTab) VelaButtonStyle.Tonal else VelaButtonStyle.Surface, icon = Icons.Filled.Send, fullWidth = false)
        }
        error?.let {
            Spacer(Modifier.height(10.dp))
            Text(it, color = VelaColors.ErrorRed, fontSize = 13.sp)
        }

        Spacer(Modifier.height(16.dp))
        VelaCard {
            Text("Share item", fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(10.dp))

            // Item selector trigger
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(VelaColors.SurfaceBase)
                    .clickable(enabled = shareableItems.isNotEmpty()) { showPicker = true }
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "Item",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 2.sp,
                        color = VelaColors.TextMuted
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        selectedItem?.name ?: if (shareableItems.isEmpty()) "No shareable items" else "Select an item",
                        fontSize = 15.sp,
                        color = if (selectedItem != null) VelaColors.TextPrimary else VelaColors.TextMuted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Icon(
                    Icons.Filled.KeyboardArrowDown,
                    contentDescription = "Select item",
                    tint = VelaColors.TextSecondary,
                    modifier = Modifier.padding(start = 8.dp)
                )
            }

            Spacer(Modifier.height(10.dp))
            VelaTextField(value = recipient, onValueChange = { recipient = it }, label = "Recipient user ID")
            Spacer(Modifier.height(10.dp))
            VelaButton(
                "Share",
                onClick = {
                    val itemId = selectedItem?.id ?: return@VelaButton
                    scope.launch(Dispatchers.IO) {
                        runCatching { VelaRepositories.sharing.sendShare(itemId, recipient.trim()) }
                            .onSuccess {
                                withContext(Dispatchers.Main) {
                                    selectedItem = null
                                    recipient = ""
                                    load()
                                }
                            }
                            .onFailure { e -> withContext(Dispatchers.Main) { error = e.message ?: "Share failed" } }
                    }
                },
                enabled = selectedItem != null && recipient.isNotBlank()
            )
        }

        Spacer(Modifier.height(16.dp))
        val filtered = shares.filter { it.direction == if (sentTab) ShareDirection.Sent else ShareDirection.Received }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(filtered, key = { it.id }) { share ->
                VelaCard {
                    Text(share.itemName, fontWeight = FontWeight.SemiBold)
                    Text(
                        if (share.direction == ShareDirection.Sent) "To: ${share.to}" else "From: ${share.from}",
                        color = VelaColors.TextSecondary,
                        fontSize = 13.sp
                    )
                    Text(share.sharedAt, color = VelaColors.TextMuted, fontSize = 12.sp)
                    Spacer(Modifier.height(10.dp))
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (share.direction == ShareDirection.Received) {
                            VelaButton("Accept", {
                                scope.launch(Dispatchers.IO) {
                                    runCatching { VelaRepositories.sharing.acceptShare(share.id) }
                                    withContext(Dispatchers.Main) { load() }
                                }
                            }, style = VelaButtonStyle.Tonal, fullWidth = false, modifier = Modifier.weight(1f))
                            VelaButton("Decline", {
                                scope.launch(Dispatchers.IO) {
                                    runCatching { VelaRepositories.sharing.declineShare(share.id) }
                                    withContext(Dispatchers.Main) { load() }
                                }
                            }, style = VelaButtonStyle.Surface, fullWidth = false, modifier = Modifier.weight(1f))
                        } else {
                            VelaButton("Revoke access", {
                                scope.launch(Dispatchers.IO) {
                                    runCatching { VelaRepositories.sharing.revokeShare(share.id) }
                                    withContext(Dispatchers.Main) { load() }
                                }
                            }, style = VelaButtonStyle.Destructive, fullWidth = false)
                        }
                    }
                }
            }
        }
    }

    if (showPicker) {
        ItemPickerDialog(
            items = shareableItems,
            onSelect = {
                selectedItem = it
                showPicker = false
            },
            onDismiss = { showPicker = false }
        )
    }
}

@Composable
private fun ItemPickerDialog(
    items: List<VaultItem>,
    onSelect: (VaultItem) -> Unit,
    onDismiss: () -> Unit
) {
    var query by remember { mutableStateOf("") }

    val filtered = items
        .filter {
            val nameMatch = it.name.contains(query, ignoreCase = true)
            val usernameMatch = (it as? VaultItem.Login)?.username?.contains(query, ignoreCase = true) == true
            nameMatch || usernameMatch
        }
        .sortedBy { it.name.lowercase() }

    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(20.dp))
                .background(VelaColors.SurfaceLow)
                .padding(20.dp)
        ) {
            Text("Select item to share", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.height(12.dp))

            VelaSearchField(query = query, onQueryChange = { query = it })

            Spacer(Modifier.height(10.dp))

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(320.dp)
            ) {
                if (filtered.isEmpty()) {
                    Column(
                        modifier = Modifier.fillMaxSize(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            Icons.Filled.SearchOff,
                            null,
                            modifier = Modifier.size(36.dp),
                            tint = VelaColors.TextMuted
                        )
                        Spacer(Modifier.height(8.dp))
                        Text("No items found", color = VelaColors.TextSecondary)
                    }
                } else {
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        items(filtered, key = { it.id }) { item ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(VelaColors.SurfaceBase)
                                    .clickable { onSelect(item) }
                                    .padding(horizontal = 14.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        item.name,
                                        fontSize = 15.sp,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    if (item is VaultItem.Login && item.username.isNotBlank()) {
                                        Text(
                                            item.username,
                                            fontSize = 12.sp,
                                            color = VelaColors.TextSecondary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }
                                val typeLabel = when (item) {
                                    is VaultItem.Login -> "Login"
                                    is VaultItem.CreditCard -> "Card"
                                    is VaultItem.SecureNote -> "Note"
                                    else -> "Item"
                                }
                                Text(
                                    typeLabel,
                                    fontSize = 12.sp,
                                    color = VelaColors.TextMuted
                                )
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(12.dp))
            VelaButton(
                text = "Cancel",
                onClick = onDismiss,
                style = VelaButtonStyle.Surface
            )
        }
    }
}
