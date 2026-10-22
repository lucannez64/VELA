package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.*
import org.json.JSONObject
import com.vela.android.core.VaultItem
import com.vela.android.core.accountsNeedingAttention
import com.vela.android.sync.SyncState
import com.vela.android.ui.components.*
import com.vela.android.ui.theme.*

@Composable
fun VaultBrowserScreen(items: List<VaultItem>, itemCount: Int, onItemClick: (VaultItem) -> Unit,
    onAddItem: () -> Unit, onLock: () -> Unit, initialFavoritesOnly: Boolean = false,
    initialAttentionOnly: Boolean = false, syncState: SyncState? = null,
    organization: VaultOrganization = VaultOrganization(), onEnableCollections: () -> Unit = {}, onMutateOrganization: (JSONObject) -> Unit = {}) {
    var showCollections by remember { mutableStateOf(false) }
    var scopePicker by remember { mutableStateOf(false) }
    var folder by remember { mutableStateOf<String?>(null) }
    var tag by remember { mutableStateOf<String?>(null) }
    var includeChildren by remember { mutableStateOf(true) }
    var query by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf<String?>(null) }
    var favoritesOnly by remember(initialFavoritesOnly) { mutableStateOf(initialFavoritesOnly) }
    var attentionOnly by remember(initialAttentionOnly) { mutableStateOf(initialAttentionOnly) }
    val attentionIds = remember(items) { items.accountsNeedingAttention() }
    val filtered = items.filter { item ->
        val matches = query.isBlank() || item.name.contains(query, true) ||
            (item is VaultItem.Login && (item.url.contains(query, true) || item.username.contains(query, true)))
        matches && (selectedType == null || item.kindLabel == selectedType) &&
            (!favoritesOnly || item.favorite) && (!attentionOnly || item.id in attentionIds) &&
            (folder == null || if(folder == "") !organization.containsFolder(item.rich.folderId) else item.rich.folderId == folder ||
                (includeChildren && organization.folderPath(item.rich.folderId).startsWith(organization.folderPath(folder!!)+" / "))) &&
            (tag == null || tag in item.rich.tagIds)
    }.sortedWith(compareByDescending<VaultItem> { it.favorite }.thenBy { it.name.lowercase() })

    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).padding(horizontal = 20.dp).padding(top = 4.dp)) {
        Box(Modifier.arrive(0)) { InstrumentBrand(onLock, syncState) }
        Row(Modifier.arrive(1), verticalAlignment = Alignment.CenterVertically) {
            InstrumentHeading("01 / Your vault",
                if (attentionOnly) "A little attention." else if (favoritesOnly) "Favourites." else "All the essentials.",
                modifier = Modifier.weight(1f))
            InstrumentIconButton(InstrumentIcons.Plus, "Add item", onAddItem)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            InstrumentPill("Collections", { showCollections = true })
            if (organization.enabled) InstrumentPill(if(folder!=null || tag!=null) "Filtered · Change" else "All folders & tags",{scopePicker=true})
        }
        SearchField(query, { query = it }, Modifier.padding(top = 0.dp).arrive(2))
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 3.dp, bottom = 7.dp).arrive(3),
            horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf(null to "All", "Login" to "Logins", "Card" to "Cards", "Note" to "Notes", "Identity" to "Identities", "Passkey" to "Passkeys").forEach { (type, label) ->
                InstrumentChip(label, type == selectedType && !favoritesOnly && !attentionOnly, {
                    selectedType = type; favoritesOnly = false; attentionOnly = false
                })
            }
            if (favoritesOnly) InstrumentChip("Favourites ×", true, { favoritesOnly = false })
            if (attentionOnly) InstrumentChip("Attention ×", true, { attentionOnly = false })
        }
        SectionHead("Saved items", Modifier.arrive(4)) {
            Text(filtered.size.toString().padStart(2, '0'), fontFamily = InstrumentMono, fontSize = 11.sp, color = VelaColors.Violet)
        }
        if (filtered.isEmpty()) {
            Column(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 8.dp, vertical = 32.dp).arrive(5),
                horizontalAlignment = Alignment.CenterHorizontally) {
                Text(if (items.isEmpty()) "A place for your essentials." else "No matches.", fontSize = 14.sp, color = VelaColors.TextPrimary)
                Spacer(Modifier.height(12.dp))
                InstrumentFine(if (items.isEmpty()) "Save your first login, card or private note." else "Try another name or item type.")
                if (items.isEmpty()) { Spacer(Modifier.height(18.dp)); InstrumentPill("Add an item", onAddItem, icon = InstrumentIcons.Plus) }
            }
        } else LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(bottom = 16.dp)) {
            itemsIndexed(filtered, key = { _, it -> it.id }) { i, item ->
                VaultItemRow(item, item.id in attentionIds, Modifier.animateItem().arrive(5 + i)) { onItemClick(item) }
            }
        }
    }
    RichDialog(showCollections,"Collections",{showCollections=false}) { CollectionsManager(organization,onEnableCollections,onMutateOrganization) }
    RichDialog(scopePicker,"Filter collections",{scopePicker=false}) {
        InstrumentPill("Clear filters",{folder=null;tag=null;scopePicker=false},Modifier.fillMaxWidth())
        SheetLabel("Folders")
        InstrumentMenuRow(null,"Unfiled") {folder="";scopePicker=false}
        organization.folders.forEach {val f=JSONObject(it); val id=f.getString("id")
            InstrumentMenuRow(null,organization.folderPath(id)) {folder=id;scopePicker=false}
        }
        InstrumentControlRow("Include subfolders") {InstrumentToggle(includeChildren,{includeChildren=it},"Include subfolders")}
        SheetLabel("Tags")
        organization.tags.forEach {val t=JSONObject(it);val id=t.getString("id")
            InstrumentMenuRow(null,t.getString("name")) {tag=id;scopePicker=false}
        }
        // Keep the last tag reachable above gesture navigation, even when the
        // dialog window reports a taller viewport than the visible screen.
        Spacer(Modifier.height(72.dp))
    }

}

/** Pill search field; the hairline turns violet while focused. */
@Composable
fun SearchField(value: String, onValueChange: (String) -> Unit, modifier: Modifier = Modifier, placeholder: String = "Search your vault") {
    var focused by remember { mutableStateOf(false) }
    val shape = RoundedCornerShape(99.dp)
    Row(
        modifier.fillMaxWidth().padding(top = 10.dp, bottom = 10.dp).heightIn(min = 48.dp).background(Ink.panel, shape)
            .border(1.dp, if (focused) VelaColors.Violet else Ink.line2, shape).padding(horizontal = 13.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        InstrumentIcon(InstrumentIcons.Search, 17.dp, VelaColors.TextMuted)
        Spacer(Modifier.width(9.dp))
        Box(Modifier.weight(1f)) {
            if (value.isEmpty()) Text(placeholder, fontSize = 12.sp, color = Ink.faint)
            BasicTextField(value, onValueChange, Modifier.fillMaxWidth().onFocusChanged { focused = it.isFocused },
                singleLine = true, textStyle = TextStyle(fontSize = 12.sp, color = VelaColors.TextPrimary),
                cursorBrush = SolidColor(VelaColors.Violet))
        }
    }
}
