package com.vela.android.ui.components

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import com.vela.android.core.*
import com.vela.android.ui.theme.VelaColors
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

@Composable
fun RichDialog(visible: Boolean, title: String, onDismiss: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    if (!visible) return
    Dialog(onDismiss, DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false, securePolicy = SecureFlagPolicy.Inherit)) {
        // A dialog window can extend under the gesture/navigation bar. Constrain the
        // sheet to the area that is actually visible, so long folder/tag lists scroll
        // instead of disappearing past the bottom edge.
        BoxWithConstraints(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.systemBars)) {
            InstrumentSheet(true, title, onDismiss, maxHeight = maxHeight * 0.94f, content = content)
        }
    }
}

/** All records start from the original JSON, preserving fields this build doesn't edit. */
@Composable
fun RichItemEditor(rich: RichData, organization: VaultOrganization, kind: String, onChange: (RichData) -> Unit) {
    var folderPicker by remember { mutableStateOf(false) }
    if (!organization.enabled) {
        InstrumentFine("Enable collections from the vault to organize items and add custom fields.", Modifier.padding(top=16.dp))
        return
    }
    SheetLabel("Organization")
    InstrumentPill("Folder · ${organization.folderPath(rich.folderId).ifEmpty { "Unfiled" }}", { folderPicker = true }, Modifier.fillMaxWidth())
    SheetLabel("Tags")
    if (organization.tags.isEmpty()) InstrumentFine("Create tags from Collections in the vault.")
    organization.tags.chunked(3).forEach { group ->
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            group.forEach { raw -> val tag=JSONObject(raw); val id=tag.getString("id")
                InstrumentChip(tag.getString("name"),id in rich.tagIds, {
                    val ids=rich.tagIds.toMutableSet(); if(!ids.add(id)) ids.remove(id)
                    onChange(rich.set("tagIds",JSONArray(ids.toList())))
                })
            }
        }
    }
    SheetLabel("Custom fields")
    rich.customFields.forEachIndexed { index, raw ->
        val field=JSONObject(raw); val type=field.getString("type")
        if (type !in listOf("text","concealed","boolean")) {
            InstrumentFine("${field.stringOrEmpty("label")} · Unsupported field, preserved read-only")
        } else {
            fun update(key:String,value:Any) = onChange(rich.setRecords("customFields",rich.customFields.toMutableList().also { it[index]=JSONObject(raw).put(key,value).toString() }))
            SheetInput("Field label",field.stringOrEmpty("label"),{update("label",it)},"e.g. Account number")
            ChipRow(listOf("Text","Secret","Boolean"),when(type){"concealed"->"Secret";"boolean"->"Boolean";else->"Text"},{ selected ->
                val newType=when(selected){"Secret"->"concealed";"Boolean"->"boolean";else->"text"}
                val changed=JSONObject(raw).put("type",newType).put("value",if(newType=="boolean") false else "")
                onChange(rich.setRecords("customFields",rich.customFields.toMutableList().also { it[index]=changed.toString() }))
            })
            if(type=="boolean") InstrumentControlRow(field.stringOrEmpty("label").ifEmpty{"Value"}) {
                InstrumentToggle(field.optBoolean("value"),{update("value",it)},"Field value")
            } else SheetInput("Value",field.stringOrEmpty("value"),{update("value",it)},secret=type=="concealed")
            TextAction("Remove field") { onChange(rich.setRecords("customFields",rich.customFields.filterIndexed { i,_-> i!=index })) }
        }
    }
    InstrumentPill("Add field",{ onChange(rich.setRecords("customFields",rich.customFields+JSONObject().put("id",UUID.randomUUID()).put("label","").put("type","text").put("value","").toString())) },Modifier.padding(top=10.dp),icon=InstrumentIcons.Plus,enabled=rich.customFields.size<128)
    if(kind=="login") {
        SheetLabel("Additional websites")
        InstrumentFine("HTTPS addresses and match rules are stored with this login. Autofill approval remains site-specific.")
        rich.additionalUrls.forEachIndexed { index,raw ->
            val url=JSONObject(raw);val mode=url.optString("match")
            if(mode !in listOf("exact","origin")) InstrumentFine("Unsupported URL rule · Preserved read-only") else {
                fun update(key:String,value:String) = onChange(rich.setRecords("additionalUrls",rich.additionalUrls.toMutableList().also { it[index]=JSONObject(raw).put(key,value).toString() }))
                SheetInput("HTTPS website",url.stringOrEmpty("url"),{update("url",it)},"https://example.test")
                ChipRow(listOf("Exact URL","Origin"),if(mode=="exact")"Exact URL" else "Origin",{update("match",if(it=="Origin")"origin" else "exact")})
                TextAction("Remove website") { onChange(rich.setRecords("additionalUrls",rich.additionalUrls.filterIndexed {i,_->i!=index})) }
            }
        }
        InstrumentPill("Add website",{ onChange(rich.setRecords("additionalUrls",rich.additionalUrls+JSONObject().put("id",UUID.randomUUID()).put("url","").put("match","exact").toString())) },Modifier.padding(top=10.dp),icon=InstrumentIcons.Plus,enabled=rich.additionalUrls.size<32)
    }
    if(kind=="identity") {
        SheetLabel("Contact & work")
        listOf("middleName" to "Middle name","preferredName" to "Preferred name","email" to "Email","phone" to "Phone","company" to "Company","jobTitle" to "Job title").forEach {(key,label)->
            SheetInput(label,rich.identity.stringOrEmpty(key),{onChange(rich.set("identityDetails",rich.identity.put(key,it)))})
        }
        SheetLabel("Addresses")
        val addresses=rich.identity.optJSONArray("addresses").records()
        addresses.forEachIndexed { index,raw ->
            val address=JSONObject(raw)
            listOf("label" to "Address label","line1" to "Street","line2" to "Apartment / suite","city" to "City","region" to "State / region","postalCode" to "Postal code","countryCode" to "Country code (2 letters)").forEach {(key,label)->
                SheetInput(label,address.stringOrEmpty(key),{value->
                    val changed=JSONObject(raw).put(key,if(key=="countryCode")value.uppercase() else value)
                    val next=addresses.toMutableList().also { it[index]=changed.toString() }
                    onChange(rich.set("identityDetails",rich.identity.put("addresses",JSONArray().apply {next.forEach {put(JSONObject(it))}})))
                })
            }
            TextAction("Remove address") {onChange(rich.set("identityDetails",rich.identity.put("addresses",JSONArray().apply {addresses.forEachIndexed {i,a->if(i!=index)put(JSONObject(a))}})))}
        }
        InstrumentPill("Add address",{onChange(rich.set("identityDetails",rich.identity.put("addresses",JSONArray().apply {addresses.forEach {put(JSONObject(it))};put(JSONObject().put("id",UUID.randomUUID()))})))},Modifier.padding(top=10.dp),icon=InstrumentIcons.Plus,enabled=addresses.size<16)
    }
    RichDialog(folderPicker,"Choose a folder",{folderPicker=false}) {
        InstrumentMenuRow(null,"Unfiled") {onChange(rich.set("folderId",""));folderPicker=false}
        organization.folders.forEach { val folder=JSONObject(it);val id=folder.getString("id")
            InstrumentMenuRow(null,organization.folderPath(id)) {onChange(rich.set("folderId",id));folderPicker=false}
        }
    }
}

@Composable
fun CollectionsManager(organization: VaultOrganization, onEnable: () -> Unit, onMutate: (JSONObject) -> Unit) {
    var section by remember { mutableStateOf("Folders") }
    var edit by remember { mutableStateOf<String?>(null) }
    var name by remember { mutableStateOf("") }
    var parent by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    fun run(action:()->Unit) { try {action();error=null;edit=null} catch(e:Exception){error=e.message ?: "Could not save changes"} }
    if(!organization.enabled) {
        InstrumentFine("Collections add nested folders, tags and rich fields. An encrypted safety copy is saved before enabling them. Older clients will need an update before they can sync edits.")
        InstrumentPill("Enable collections",{run(onEnable)},Modifier.fillMaxWidth().padding(top=16.dp),style=PillStyle.Primary)
    } else {
        ChipRow(listOf("Folders","Tags"),section,{section=it})
        InstrumentPill(if(section=="Folders")"New folder" else "New tag",{name="";parent="";edit="new"},Modifier.padding(vertical=12.dp),icon=InstrumentIcons.Plus)
        val records=if(section=="Folders")organization.folders else organization.tags
        records.forEach {raw->val record=JSONObject(raw);val id=record.getString("id")
            InstrumentMenuRow(null,if(section=="Folders")organization.folderPath(id) else record.getString("name")) {
                name=record.getString("name");parent=record.stringOrEmpty("parentId");edit=raw
            }
        }
        if(records.isEmpty()) InstrumentFine("No ${section.lowercase()} yet.")
    }
    error?.let {Text(it,color=VelaColors.ErrorRed)}
    RichDialog(edit!=null,if(edit=="new")"New ${section.dropLast(1).lowercase()}" else "Edit ${section.dropLast(1).lowercase()}",{edit=null}) {
        SheetInput("Name",name,{name=it})
        if(section=="Folders") {
            SheetLabel("Parent folder")
            Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                InstrumentChip("Top level",parent.isEmpty(),{parent=""})
                organization.folders.forEach {val f=JSONObject(it);val id=f.getString("id")
                    if(edit=="new" || JSONObject(edit ?: "{}").optString("id")!=id) InstrumentChip(organization.folderPath(id),parent==id,{parent=id})
                }
            }
        }
        error?.let {Text(it,color=VelaColors.ErrorRed)}
        InstrumentPill("Save",{
            val action=JSONObject().put("name",name.trim()).put("operation",if(section=="Folders") {if(edit=="new")"createFolder" else "updateFolder"} else {if(edit=="new")"createTag" else "renameTag"})
            if(edit!="new") action.put("id",JSONObject(edit!!).getString("id"))
            if(section=="Folders") action.put("parentId",parent.ifEmpty{null})
            run {onMutate(action)}
        },Modifier.fillMaxWidth().padding(top=20.dp),style=PillStyle.Primary,enabled=name.isNotBlank())
        if(edit!=null && edit!="new") {
            InstrumentFine("Deleting this ${section.dropLast(1).lowercase()} keeps its items in the vault.",Modifier.padding(top=14.dp))
            VelaButton("Delete ${section.dropLast(1).lowercase()}",{
                run {onMutate(JSONObject().put("operation",if(section=="Folders")"deleteFolder" else "deleteTag").put("id",JSONObject(edit!!).getString("id")))}
            },style=VelaButtonStyle.Destructive)
        }
    }
}
