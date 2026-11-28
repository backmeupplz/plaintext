package com.borodutch.plaintext

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.RemoveCircleOutline
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import uniffi.plaintext_ffi.FieldData
import uniffi.plaintext_ffi.ItemData
import uniffi.plaintext_ffi.Recipe
import uniffi.plaintext_ffi.SectionData
import uniffi.plaintext_ffi.generatePassword
import uniffi.plaintext_ffi.totpCode

private val fieldKinds = listOf(
    "text" to "Text", "concealed" to "Hidden", "url" to "Website", "email" to "Email", "phone" to "Phone",
    "date" to "Date", "month_year" to "Month and year", "otp" to "One-time code", "address" to "Address", "ssh_key" to "SSH key",
)

@Composable
fun ItemEditor(r: Route.Edit) {
    val model = LocalContext.current.model
    val original = remember(r) { r.data }
    var d by remember(r) { mutableStateOf(r.data) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirmDiscard by remember { mutableStateOf(false) }
    var scanning by remember { mutableStateOf(false) }
    val loginish = d.kind == "login" || d.kind == "password"
    val vault = model.vault(r.account, r.vault)

    fun close() = model.pop()
    fun back() { if (d != original) confirmDiscard = true else close() }
    fun save() {
        if (d.totp.isNotBlank() && totpCode(d.totp.trim()) == null) { error = "That isn't a valid one-time code setup."; return }
        busy = true
        error = null
        val data = d
        model.act {
            try {
                val id = model.call { it.putItem(r.account, r.vault, r.item, data) }
                model.reload()
                close()
                if (r.item == null) model.push(Route.Item(ItemRef(r.account, r.vault, id)))
                model.flash("Saved")
            } catch (e: Exception) {
                error = errorText(e)
            } finally { busy = false }
        }
    }
    BackHandler { if (scanning) scanning = false else back() }

    if (scanning) {
        Screen("Scan QR code", onBack = { scanning = false }, close = true) { m ->
            Column(m) {
                Scanner("Scan the QR code the website shows when you turn on two-factor authentication.") { code ->
                    if (totpCode(code) == null) return@Scanner "That isn't a one-time code setup."
                    d = d.copy(totp = code)
                    scanning = false
                    null
                }
            }
        }
        return
    }

    Screen(
        if (r.item == null) "New ${kindName(d.kind)}" else "Edit", onBack = ::back, close = true,
        actions = { TextButton(onClick = ::save, enabled = !busy) { Text("Save") } },
    ) { m ->
        Column(m.imePadding().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            ErrorNote(error)
            Field("Title", d.title, { d = d.copy(title = it) }, placeholder = kindName(d.kind))
            if (vault != null) Text("In ${vault.name}", color = P.muted, style = MaterialTheme.typography.bodySmall)
            if (loginish) {
                if (d.kind == "login") Field("Username", d.username, { d = d.copy(username = it) }, kind = Input.Username)
                PasswordEditor(d.password) { d = d.copy(password = it) }
                if (d.kind == "login") {
                    d.urls.forEachIndexed { i, u ->
                        Field("Website", u, { v -> d = d.copy(urls = d.urls.toMutableList().also { it[i] = v }) }, kind = Input.Url,
                            trailing = { IconButton(onClick = { d = d.copy(urls = d.urls.filterIndexed { j, _ -> j != i }) }) { Icon(Icons.Rounded.RemoveCircleOutline, "Remove website", tint = P.muted) } })
                    }
                    TextButton(onClick = { d = d.copy(urls = d.urls + "") }) { Icon(Icons.Rounded.Add, null); Spacer(Modifier.size(6.dp)); Text("Add website") }
                    Field(
                        "One-time code", d.totp, { d = d.copy(totp = it) }, kind = Input.Secret, placeholder = "Paste an otpauth:// link or the setup key",
                        trailing = { IconButton(onClick = { scanning = true }) { Icon(Icons.Rounded.QrCodeScanner, "Scan QR code", tint = P.accent) } },
                    )
                }
            }
            d.sections.forEachIndexed { si, s ->
                SectionEditor(s, onChange = { ns -> d = d.copy(sections = d.sections.toMutableList().also { it[si] = ns }) })
            }
            AddField { kind, label ->
                val sections = d.sections.toMutableList()
                val f = FieldData(label, kind, "", "")
                if (sections.isEmpty()) sections += SectionData("", listOf(f)) else sections[sections.lastIndex] = sections.last().copy(fields = sections.last().fields + f)
                d = d.copy(sections = sections)
            }
            Field("Notes", d.notes, { d = d.copy(notes = it) }, singleLine = false)
            Field("Tags", d.tags.joinToString(", "), { d = d.copy(tags = it.split(",").map { t -> t.trimStart() }) }, note = "Separate tags with commas.")
            Spacer(Modifier.size(48.dp))
        }
    }
    if (confirmDiscard) AlertDialog(
        onDismissRequest = { confirmDiscard = false },
        title = { Text("Discard your changes?") },
        confirmButton = { TextButton(onClick = { confirmDiscard = false; close() }) { Text("Discard changes", color = P.danger) } },
        dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Text("Keep editing") } },
    )
}

@Composable
private fun SectionEditor(s: SectionData, onChange: (SectionData) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (s.title.isNotEmpty()) Text(s.title, color = P.muted, style = MaterialTheme.typography.labelLarge)
        s.fields.forEachIndexed { fi, f ->
            fun set(nf: FieldData) = onChange(s.copy(fields = s.fields.toMutableList().also { it[fi] = nf }))
            val remove: @Composable () -> Unit = {
                IconButton(onClick = { onChange(s.copy(fields = s.fields.filterIndexed { j, _ -> j != fi })) }) { Icon(Icons.Rounded.RemoveCircleOutline, "Remove field", tint = P.muted) }
            }
            when {
                f.kind == "concealed" && f.label.contains("password", ignoreCase = true) -> PasswordEditor(f.value, f.label) { set(f.copy(value = it)) }
                concealed(f.kind) || f.kind == "otp" -> Field(f.label.ifEmpty { "Hidden" }, f.value, { set(f.copy(value = it)) }, kind = Input.Password, singleLine = f.kind != "ssh_key")
                f.kind == "menu" || f.kind == "card_type" || f.kind == "boolean" -> Field(f.label, f.value, { set(f.copy(value = it)) }, trailing = remove)
                else -> Field(
                    f.label.ifEmpty { "Field" }, f.value, { set(f.copy(value = it)) },
                    kind = when (f.kind) { "url" -> Input.Url; "card_number", "phone" -> Input.Number; else -> Input.Text },
                    singleLine = f.kind != "address", mono = f.kind == "card_number", trailing = remove,
                    placeholder = when (f.kind) { "date" -> "YYYY-MM-DD"; "month_year" -> "MM/YYYY"; else -> null },
                )
            }
        }
    }
}

@Composable
private fun AddField(onAdd: (String, String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        TextButton(onClick = { open = true }) { Icon(Icons.Rounded.Add, null); Spacer(Modifier.size(6.dp)); Text("Add field") }
        DropdownMenu(open, { open = false }) {
            fieldKinds.forEach { (k, name) -> DropdownMenuItem({ Text(name) }, { open = false; onAdd(k, name) }) }
        }
    }
}

private enum class Gen { Random, Words, Pin }

/** The password field with the generator inline: refresh, and a disclosure with the options and strength. */
@Composable
fun PasswordEditor(value: String, label: String = "Password", onChange: (String) -> Unit) {
    var shown by remember { mutableStateOf(false) }
    var options by remember { mutableStateOf(false) }
    var gen by remember { mutableStateOf(Gen.Random) }
    var length by remember { mutableStateOf(20f) }
    var words by remember { mutableStateOf(4f) }
    var digits by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    fun generate() = onChange(
        generatePassword(
            when (gen) {
                Gen.Random -> Recipe.Random(length.toUInt(), digits, symbols)
                Gen.Words -> Recipe.Memorable(words.toUInt(), "-", false)
                Gen.Pin -> Recipe.Pin(length.toUInt().coerceAtMost(12u))
            },
        ),
    )
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Field(
            label, value, onChange, kind = Input.Password, revealed = shown,
            trailing = {
                Row {
                    IconButton(onClick = { shown = !shown }) { Icon(if (shown) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility, if (shown) "Hide password" else "Show password", tint = P.muted) }
                    IconButton(onClick = ::generate) { Icon(Icons.Rounded.Refresh, "Generate a new password", tint = P.accent) }
                }
            },
        )
        StrengthMeter(value)
        TextButton(onClick = { options = !options }) {
            Text("Generator options")
            Icon(if (options) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore, null)
        }
        if (options) {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                Gen.entries.forEachIndexed { i, g ->
                    SegmentedButton(gen == g, { gen = g; generate() }, SegmentedButtonDefaults.itemShape(i, Gen.entries.size)) {
                        Text(when (g) { Gen.Random -> "Random"; Gen.Words -> "Words"; Gen.Pin -> "PIN" })
                    }
                }
            }
            if (gen == Gen.Words) {
                Text("Words ${words.toInt()}", color = P.muted)
                Slider(words, { words = it; generate() }, valueRange = 3f..10f, steps = 6)
            } else {
                Text("Length ${length.toInt()}", color = P.muted)
                Slider(length, { length = it; generate() }, valueRange = if (gen == Gen.Pin) 4f..12f else 8f..64f)
            }
            if (gen == Gen.Random) {
                Row(verticalAlignment = Alignment.CenterVertically) { Text("Digits", Modifier.weight(1f), color = P.fg); Switch(digits, { digits = it; generate() }) }
                Row(verticalAlignment = Alignment.CenterVertically) { Text("Symbols", Modifier.weight(1f), color = P.fg); Switch(symbols, { symbols = it; generate() }) }
            }
        }
    }
}
