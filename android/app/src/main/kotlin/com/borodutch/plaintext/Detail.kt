package com.borodutch.plaintext

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.rounded.Archive
import androidx.compose.material.icons.rounded.AttachFile
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Star
import androidx.compose.material.icons.rounded.StarBorder
import androidx.compose.material.icons.rounded.TextFields
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import uniffi.plaintext_ffi.FileData
import uniffi.plaintext_ffi.ItemData
import uniffi.plaintext_ffi.Role
import uniffi.plaintext_ffi.TotpCode
import uniffi.plaintext_ffi.totpCode
import java.io.File
import java.util.UUID

/** Field kinds whose values are secrets: shown as dots until revealed, copied as sensitive. */
fun concealed(kind: String) = kind == "concealed" || kind == "ssh_key"

/**
 * A file name that can't leave the folder it's written to: its last path part, without control characters.
 * ponytail: mirrors core's `safe_file_name`; switch to the Rust export once the FFI has it (after PR #14).
 */
fun safeName(name: String): String {
    val base = name.substringAfterLast('/').substringAfterLast('\\').filter { it >= ' ' && it != '\u007f' }.trim()
    return if (base.isEmpty() || base == "." || base == "..") "attachment" else base.take(120)
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ItemDetail(ref: ItemRef) {
    val context = LocalContext.current
    val model = context.model
    val data = remember(ref, model.items, model.vaults) { runCatching { model.core.item(ref.account, ref.vault, ref.item) }.getOrNull() }
    if (data == null) {
        Screen("Item", onBack = { model.pop() }) { m -> Box(m) { EmptyState(Icons.Rounded.Archive, "This item is no longer here.") } }
        return
    }
    val vault = model.vault(ref.account, ref.vault)
    val canEdit = vault?.role != null && vault.role != Role.READER
    var more by remember { mutableStateOf(false) }
    var sharing by remember { mutableStateOf(false) }
    var moving by remember { mutableStateOf(false) }
    var large by remember { mutableStateOf<String?>(null) }
    val watch = model.watch.firstOrNull { it.accountId == ref.account && it.vaultId == ref.vault && it.id == ref.item }

    Screen(
        data.title.ifEmpty { "Untitled" }, onBack = { model.pop() },
        actions = {
            IconButton(onClick = { model.setFlags(ref, !data.favorite, data.archived) }) {
                Icon(if (data.favorite) Icons.Rounded.Star else Icons.Rounded.StarBorder, if (data.favorite) "Remove from Favorites" else "Add to Favorites")
            }
            if (canEdit) IconButton(onClick = { model.edit(ref) }) { Icon(Icons.Rounded.Edit, "Edit") }
            Box {
                IconButton(onClick = { more = true }) { Icon(Icons.Rounded.MoreVert, "More actions") }
                DropdownMenu(more, { more = false }) {
                    DropdownMenuItem({ Text("Share…") }, { more = false; sharing = true }, leadingIcon = { Icon(Icons.Rounded.Share, null) })
                    if (canEdit) DropdownMenuItem({ Text("Move to vault…") }, { more = false; moving = true })
                    if (canEdit) DropdownMenuItem({ Text(if (data.archived) "Unarchive" else "Archive") }, { more = false; model.setFlags(ref, data.favorite, !data.archived) }, leadingIcon = { Icon(Icons.Rounded.Archive, null) })
                    if (canEdit) DropdownMenuItem({ Text("Delete", color = P.danger) }, { more = false; model.delete(ref, data.title) }, leadingIcon = { Icon(Icons.Rounded.Delete, null, tint = P.danger) })
                }
            }
        },
    ) { m ->
        Column(m.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp), modifier = Modifier.padding(vertical = 8.dp)) {
                Monogram(data.title, 56)
                Column {
                    Text(data.title.ifEmpty { "Untitled" }, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = P.fg)
                    Text(listOfNotNull(vault?.name, kindName(data.kind)).joinToString(" · "), color = P.muted)
                }
            }
            if (watch != null || model.breached[ref.key] != null) WatchNotes(watch, model.breached[ref.key])

            Group {
                if (data.username.isNotEmpty()) FieldRow("Username", data.username, secret = false, onLarge = null)
                if (data.password.isNotEmpty()) FieldRow("Password", data.password, secret = true, onLarge = { large = data.password })
                if (data.totp.isNotEmpty()) TotpRow(data.totp)
                data.urls.forEach { u -> UrlRow(u) }
            }
            data.sections.forEach { s ->
                val fields = s.fields.filter { it.value.isNotEmpty() }
                if (fields.isEmpty()) return@forEach
                if (s.title.isNotEmpty()) Text(s.title, color = P.muted, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 8.dp))
                Group {
                    fields.forEach { f ->
                        when {
                            f.kind == "otp" -> TotpRow(f.value, f.label)
                            f.kind == "url" -> UrlRow(f.value, f.label)
                            else -> FieldRow(f.label.ifEmpty { "Field" }, f.value, secret = concealed(f.kind), mono = concealed(f.kind) || f.kind == "card_number", onLarge = if (concealed(f.kind)) ({ large = f.value }) else null)
                        }
                    }
                }
            }
            if (data.notes.isNotEmpty()) {
                // Plain text only: links in notes are never tappable (audit finding 2).
                Group { Column(Modifier.padding(12.dp)) { Text("Notes", color = P.muted, style = MaterialTheme.typography.labelLarge); Text(data.notes, color = P.fg) } }
            }
            if (data.tags.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    data.tags.forEach { Text("#$it", color = P.muted, modifier = Modifier.clip(RoundedCornerShape(6.dp)).background(P.surface).padding(horizontal = 8.dp, vertical = 4.dp)) }
                }
            }
            Attachments(ref, data, canEdit)
            if (data.passwordHistory.isNotEmpty()) {
                Text("Password history", color = P.muted, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 8.dp))
                Group { data.passwordHistory.forEach { FieldRow(dateText(it.changed.toLong()), it.password, secret = true, onLarge = null) } }
            }
            if (data.history.isNotEmpty() && canEdit) {
                Text("Earlier versions", color = P.muted, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 8.dp))
                Group {
                    data.history.forEachIndexed { i, v ->
                        Row(Modifier.fillMaxWidth().padding(start = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(v.title.ifEmpty { "Untitled" }, color = P.fg)
                                Text(dateText(v.updated.toLong()), color = P.muted, style = MaterialTheme.typography.bodySmall)
                            }
                            TextButton(onClick = {
                                model.act {
                                    model.call { it.restoreVersion(ref.account, ref.vault, ref.item, i.toUInt()) }
                                    model.reload()
                                    model.flash("Version restored")
                                }
                            }) { Text("Restore") }
                        }
                    }
                }
            }
            Text("Created ${dateText(data.created.toLong())} · Updated ${dateText(data.updated.toLong())}", color = P.muted, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 16.dp))
        }
    }
    large?.let { LargeType(it) { large = null } }
    if (sharing) ShareItemSheet(ref, data.title) { sharing = false }
    if (moving) MoveSheet(ref) { moving = false }
}

/** Rows grouped on a surface card, as in a settings list. */
@Composable
fun Group(content: @Composable () -> Unit) {
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(P.surface).padding(vertical = 4.dp)) { content() }
}

/** Label above value. Tapping copies; secrets show dots with reveal and large-type buttons, never selectable text. */
@Composable
fun FieldRow(label: String, value: String, secret: Boolean, mono: Boolean = secret, onLarge: (() -> Unit)?) {
    val model = LocalContext.current.model
    var shown by remember(value) { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().clickable { model.copy(value, label, sensitive = secret) }.heightIn(min = 56.dp).padding(start = 12.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, color = P.muted, style = MaterialTheme.typography.labelMedium)
            Text(
                if (secret && !shown) "••••••••••••" else value, color = P.fg,
                fontFamily = if (mono || (secret && shown)) Mono else null, style = MaterialTheme.typography.bodyLarge,
            )
        }
        if (secret) IconButton(onClick = { shown = !shown }) { Icon(if (shown) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility, if (shown) "Hide $label" else "Reveal $label", tint = P.muted) }
        if (onLarge != null) IconButton(onClick = onLarge) { Icon(Icons.Rounded.TextFields, "Show $label in large type", tint = P.muted) }
        IconButton(onClick = { model.copy(value, label, sensitive = secret) }) { Icon(Icons.Rounded.ContentCopy, "Copy $label", tint = P.accent) }
    }
}

@Composable
private fun UrlRow(url: String, label: String = "Website") {
    val context = LocalContext.current
    Row(
        Modifier.fillMaxWidth().clickable { openUrl(context, url) }.heightIn(min = 56.dp).padding(start = 12.dp, end = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, color = P.muted, style = MaterialTheme.typography.labelMedium)
            Text(url, color = P.accent)
        }
        IconButton(onClick = { context.model.copy(url, label, sensitive = false) }) { Icon(Icons.Rounded.ContentCopy, "Copy $label", tint = P.muted) }
        Icon(Icons.AutoMirrored.Rounded.OpenInNew, null, tint = P.muted, modifier = Modifier.padding(end = 12.dp))
    }
}

fun openUrl(context: Context, url: String) {
    val u = if (url.contains("://")) url else "https://$url"
    if (!u.startsWith("https://") && !u.startsWith("http://")) return
    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(u)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
}

/** The current code with a countdown ring; tap copies; the next code shows in the last five seconds. */
@Composable
fun TotpRow(spec: String, label: String = "One-time code") {
    val model = LocalContext.current.model
    var code by remember(spec) { mutableStateOf<TotpCode?>(totpCode(spec)) }
    LaunchedEffect(spec) { while (true) { code = totpCode(spec); delay(1_000) } }
    val c = code
    if (c == null) { FieldRow(label, "That one-time code setup isn't valid.", secret = false, onLarge = null); return }
    val grouped = { s: String -> if (s.length == 6) s.take(3) + " " + s.drop(3) else s }
    Row(
        Modifier.fillMaxWidth().clickable { model.copy(c.code, "One-time code") }.heightIn(min = 56.dp).padding(start = 12.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, color = P.muted, style = MaterialTheme.typography.labelMedium)
            Text(grouped(c.code), color = P.fg, fontFamily = Mono, style = MaterialTheme.typography.titleLarge)
            if (c.remaining <= 5u) Text("Next: ${grouped(c.next)}", color = P.muted, fontFamily = Mono, style = MaterialTheme.typography.bodySmall)
        }
        Box(contentAlignment = Alignment.Center, modifier = Modifier.semantics { contentDescription = "${c.remaining} seconds left" }) {
            CircularProgressIndicator(progress = { c.remaining.toFloat() / c.period.toFloat() }, modifier = Modifier.size(32.dp), strokeWidth = 3.dp, color = if (c.remaining <= 5u) P.warn else P.accent, trackColor = P.line)
            Text("${c.remaining}", style = MaterialTheme.typography.labelSmall, color = P.muted)
        }
        IconButton(onClick = { model.copy(c.code, "One-time code") }) { Icon(Icons.Rounded.ContentCopy, "Copy one-time code", tint = P.accent) }
    }
}

@Composable
private fun WatchNotes(w: uniffi.plaintext_ffi.WatchItem?, breached: ULong?) {
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(P.surface).padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        if (breached != null) Note("This password appeared in $breached data breaches. Change it.")
        w?.findings?.forEach { f ->
            when (f) {
                uniffi.plaintext_ffi.Finding.WEAK -> Note("This password is easy to guess. Change it.")
                uniffi.plaintext_ffi.Finding.REUSED -> Note("This password is reused in ${w.reusedWith} other ${if (w.reusedWith == 1u) "item" else "items"}. Change it.")
                uniffi.plaintext_ffi.Finding.UNSECURED -> Note("This website address doesn't use https.")
                uniffi.plaintext_ffi.Finding.NO_TWO_FACTOR -> Note("This site offers two-factor authentication. Add a one-time code.")
            }
        }
    }
}

/** One character per box; digits and symbols tinted differently. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun LargeType(text: String, onDismiss: () -> Unit) {
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Column(Modifier.padding(16.dp).clip(RoundedCornerShape(14.dp)).background(P.bg).clickable(onClick = onDismiss).padding(16.dp)) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                text.forEachIndexed { i, ch ->
                    val color = when {
                        ch.isDigit() -> P.accent
                        !ch.isLetter() -> P.warn
                        else -> P.fg
                    }
                    Column(
                        Modifier.clip(RoundedCornerShape(6.dp)).background(if (i % 2 == 0) P.surface else P.code).padding(horizontal = 6.dp, vertical = 4.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(ch.toString(), fontFamily = Mono, fontSize = 30.sp, color = color, fontWeight = FontWeight.SemiBold)
                        Text("${i + 1}", fontSize = 10.sp, color = P.muted)
                    }
                }
            }
            TextButton(onClick = onDismiss, modifier = Modifier.align(Alignment.End)) { Text("Done") }
        }
    }
}

@Composable
private fun Attachments(ref: ItemRef, data: ItemData, canEdit: Boolean) {
    val context = LocalContext.current
    val model = context.model
    var busy by remember { mutableStateOf(false) }
    var saving by remember { mutableStateOf<FileData?>(null) }
    val add = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        busy = true
        model.act {
            try {
                val (name, bytes) = withContext(Dispatchers.IO) { readUri(context, uri) }
                model.call { it.attachFile(ref.account, ref.vault, ref.item, name, bytes) }
                model.reload()
                model.flash("Attached $name")
            } finally { busy = false }
        }
    }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val f = saving ?: return@rememberLauncherForActivityResult
        saving = null
        if (uri == null) return@rememberLauncherForActivityResult
        model.act {
            val bytes = model.call { it.downloadFile(ref.account, ref.vault, ref.item, f.id) }
            withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } }
            model.flash("Saved ${safeName(f.name)}")
        }
    }
    if (data.files.isEmpty() && !canEdit) return
    Text("Attachments", color = P.muted, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 8.dp))
    Group {
        data.files.forEach { f ->
            var menu by remember { mutableStateOf(false) }
            Box {
                Row(Modifier.fillMaxWidth().clickable { menu = true }.heightIn(min = 52.dp).padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Icon(Icons.Rounded.AttachFile, null, tint = P.muted)
                    Column(Modifier.weight(1f)) {
                        Text(safeName(f.name), color = P.fg)
                        Text(android.text.format.Formatter.formatShortFileSize(context, f.size.toLong()), color = P.muted, style = MaterialTheme.typography.bodySmall)
                    }
                }
                DropdownMenu(menu, { menu = false }) {
                    DropdownMenuItem({ Text("Open") }, { menu = false; model.act { shareFile(context, ref, f, Intent.ACTION_VIEW) } })
                    DropdownMenuItem({ Text("Share…") }, { menu = false; model.act { shareFile(context, ref, f, Intent.ACTION_SEND) } })
                    DropdownMenuItem({ Text("Save to Files…") }, { menu = false; saving = f; model.external = true; save.launch(safeName(f.name)) })
                }
            }
        }
        if (canEdit) {
            Row(Modifier.fillMaxWidth().clickable(enabled = !busy) { model.external = true; add.launch(arrayOf("*/*")) }.heightIn(min = 52.dp).padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                if (busy) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp) else Icon(Icons.Rounded.AttachFile, null, tint = P.accent)
                Text("Add attachment", color = P.accent)
            }
        }
    }
}

/** A picked file's name and bytes (attachments are capped at 64 MB by the server). */
fun readUri(context: Context, uri: Uri): Pair<String, ByteArray> {
    val name = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    } ?: "attachment"
    val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: throw UserError("Couldn't read that file.")
    return safeName(name) to bytes
}

/** Decrypt into a fresh folder in the cache (wiped on lock and sign-out) and hand it to another app. */
private suspend fun shareFile(context: Context, ref: ItemRef, f: FileData, action: String) {
    val model = context.model
    val bytes = model.call { it.downloadFile(ref.account, ref.vault, ref.item, f.id) }
    val file = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, "open/${UUID.randomUUID()}").apply { mkdirs() }
        File(dir, safeName(f.name)).apply { writeBytes(bytes) }
    }
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.files", file)
    val type = context.contentResolver.getType(uri) ?: "application/octet-stream"
    val intent = Intent(action).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    if (action == Intent.ACTION_SEND) intent.setType(type).putExtra(Intent.EXTRA_STREAM, uri) else intent.setDataAndType(uri, type)
    model.external = true
    runCatching { context.startActivity(Intent.createChooser(intent, null)) }
}

@Composable
private fun MoveSheet(ref: ItemRef, onDismiss: () -> Unit) {
    val model = LocalContext.current.model
    val targets = model.vaults.filter { it.role != null && it.role != Role.READER && !(it.accountId == ref.account && it.id == ref.vault) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Move to vault") },
        text = {
            Column {
                if (targets.isEmpty()) Text("There's no other vault you can move it to.", color = P.muted)
                targets.forEach { v ->
                    Row(Modifier.fillMaxWidth().clickable {
                        onDismiss()
                        model.act {
                            val nid = model.call { it.moveItem(ref.account, ref.vault, ref.item, v.accountId, v.id) }
                            model.stack.removeAll { it is Route.Item && it.ref == ref }
                            model.reload()
                            model.push(Route.Item(ItemRef(v.accountId, v.id, nid)))
                            model.flash("Moved to ${v.name}")
                        }
                    }.heightIn(min = 52.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column {
                            Text(v.name.ifEmpty { "Untitled vault" }, color = P.fg)
                            if (model.accounts.size > 1) model.account(v.accountId)?.let { Text(accountLabel(it.server, it.username), color = P.muted, style = MaterialTheme.typography.bodySmall) }
                        }
                    }
                    HorizontalDivider(color = P.line)
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
