package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.SearchOff
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.VaultItem
import com.vela.android.ui.components.FaviconIcon
import com.vela.android.ui.components.StatusBadge
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaSearchField
import com.vela.android.ui.theme.VelaColors

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun VaultBrowserScreen(
    items: List<VaultItem>,
    itemCount: Int,
    onItemClick: (VaultItem) -> Unit,
    onAddItem: () -> Unit,
    onLock: () -> Unit
) {
    var query by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf<String?>(null) }
    var favoritesOnly by remember { mutableStateOf(false) }

    val filteredItems = items
        .asSequence()
        .filter { item ->
            val matchesQuery = query.isEmpty() ||
                item.name.contains(query, ignoreCase = true) ||
                (item is VaultItem.Login && item.url.contains(query, ignoreCase = true)) ||
                (item is VaultItem.Login && item.username.contains(query, ignoreCase = true))
            val matchesType = selectedType == null || item.typeLabel == selectedType
            val matchesFavorite = !favoritesOnly || item.favorite
            matchesQuery && matchesType && matchesFavorite
        }
        // Favorites pin to the top, then alphabetical — mirrors what users
        // expect from the desktop list.
        .sortedWith(compareByDescending<VaultItem> { it.favorite }.thenBy { it.name.lowercase() })
        .toList()

    Box(modifier = Modifier.fillMaxSize().background(VelaColors.SurfaceBase)) {
        Column(modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(16.dp))

            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "Vault",
                        fontSize = 28.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )
                    Text(
                        "$itemCount item${if (itemCount != 1) "s" else ""}",
                        color = VelaColors.TextSecondary,
                        fontSize = 14.sp
                    )
                }
                VelaButton(
                    text = "Lock",
                    onClick = onLock,
                    style = VelaButtonStyle.Tonal,
                    icon = Icons.Filled.Lock,
                    fullWidth = false,
                    modifier = Modifier
                )
            }

            Spacer(Modifier.height(20.dp))

            // Search
            VelaSearchField(query = query, onQueryChange = { query = it })

            Spacer(Modifier.height(14.dp))

            // Type filter chips
            val types = listOf(
                null to "All",
                "login" to "Logins",
                "card" to "Cards",
                "note" to "Notes"
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                types.forEach { (type, label) ->
                    val isSelected = selectedType == type
                    FilterChip(
                        label = label,
                        selected = isSelected,
                        onClick = { selectedType = type; if (!isSelected) favoritesOnly = false }
                    )
                }
            }
            val favoriteCount = items.count { it.favorite }
            if (favoriteCount > 0) {
                Spacer(Modifier.height(8.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        label = "Favorites · $favoriteCount",
                        selected = favoritesOnly,
                        leading = Icons.Filled.Star,
                        onClick = { favoritesOnly = !favoritesOnly }
                    )
                }
            }

            Spacer(Modifier.height(16.dp))

            // Items list
            if (filteredItems.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize().weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Filled.SearchOff, null,
                            modifier = Modifier.size(48.dp),
                            tint = VelaColors.TextMuted
                        )
                        Spacer(Modifier.height(16.dp))
                        Text(
                            when {
                                query.isNotEmpty() -> "No items matching \"$query\""
                                favoritesOnly -> "No favorites yet"
                                else -> "Vault is empty"
                            },
                            color = VelaColors.TextSecondary,
                            fontSize = 16.sp
                        )
                        if (query.isEmpty() && !favoritesOnly) {
                            Spacer(Modifier.height(8.dp))
                            Text("Tap + to add your first item", color = VelaColors.TextMuted, fontSize = 14.sp)
                        }
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredItems, key = { it.id }) { item ->
                        VaultItemRow(item = item, onClick = { onItemClick(item) })
                    }
                    item { Spacer(Modifier.height(80.dp)) }
                }
            }
        }

        // FAB
        FloatingActionButton(
            onClick = onAddItem,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(24.dp),
            containerColor = VelaColors.Green,
            contentColor = VelaColors.GreenDark,
            shape = RoundedCornerShape(16.dp)
        ) {
            Icon(Icons.Filled.Add, "Add item")
        }
    }
}

@Composable
fun VaultItemRow(item: VaultItem, onClick: () -> Unit) {
    val icon = when (item) {
        is VaultItem.Login -> Icons.Filled.Key
        is VaultItem.CreditCard -> Icons.Filled.CreditCard
        is VaultItem.SecureNote -> Icons.Filled.Description
        is VaultItem.BreachMonitor -> Icons.Filled.Description
        else -> Icons.Filled.Description
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(VelaColors.SurfaceLow)
            .clickable(onClick = onClick)
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(42.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(VelaColors.Green.copy(alpha = 0.1f)),
            contentAlignment = Alignment.Center
        ) {
            if (item is VaultItem.Login && item.url.isNotBlank()) {
                FaviconIcon(
                    url = item.url,
                    fallback = icon,
                    size = 22.dp,
                    shape = RoundedCornerShape(6.dp)
                )
            } else {
                Icon(icon, null, modifier = Modifier.size(22.dp), tint = VelaColors.Green)
            }
        }

        Spacer(Modifier.width(14.dp))

        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    item.name,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false)
                )
                if (item.favorite) {
                    Spacer(Modifier.width(6.dp))
                    Icon(
                        Icons.Filled.Star, null,
                        modifier = Modifier.size(14.dp),
                        tint = VelaColors.WarningAmber
                    )
                }
            }
            Spacer(Modifier.height(3.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusBadge(text = item.typeLabel)
                if (item is VaultItem.Login && item.username.isNotBlank()) {
                    Spacer(Modifier.width(8.dp))
                    Text(
                        item.username,
                        color = VelaColors.TextSecondary,
                        fontSize = 12.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                } else if (item is VaultItem.Login && item.url.isNotBlank()) {
                    Spacer(Modifier.width(8.dp))
                    Text(
                        item.url,
                        color = VelaColors.TextMuted,
                        fontSize = 12.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

private val VaultItem.typeLabel: String
    get() = when (this) {
        is VaultItem.Login -> "login"
        is VaultItem.CreditCard -> "card"
        is VaultItem.SecureNote -> "note"
        is VaultItem.FileBlob -> "file"
        is VaultItem.BreachMonitor -> "breach"
        else -> "item"
    }

@Composable
private fun FilterChip(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    leading: androidx.compose.ui.graphics.vector.ImageVector? = null
) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(20.dp))
            .background(if (selected) VelaColors.Green.copy(alpha = 0.15f) else VelaColors.SurfaceHigh)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (leading != null) {
            Icon(
                leading, null,
                modifier = Modifier.size(14.dp),
                tint = if (selected) VelaColors.Green else VelaColors.WarningAmber
            )
            Spacer(Modifier.width(6.dp))
        }
        Text(
            label,
            color = if (selected) VelaColors.Green else VelaColors.TextSecondary,
            fontSize = 13.sp,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
        )
    }
}
