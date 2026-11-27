package com.borodutch.plaintext

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Group
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import uniffi.plaintext_ffi.AuditData
import uniffi.plaintext_ffi.MemberInfo
import uniffi.plaintext_ffi.Role

fun roleName(r: Role?) = when (r) {
    Role.OWNER -> "Can manage"
    Role.WRITER -> "Can edit"
    Role.READER -> "Can view"
    null -> "Access ended"
}

/** Expiry choices, in seconds from now (0 = never). */
val expiries = listOf(0L to "Never", 86_400L to "In a day", 604_800L to "In a week", 2_592_000L to "In 30 days")
fun expiresAt(seconds: Long): ULong? = if (seconds == 0L) null else (System.currentTimeMillis() / 1000 + seconds).toULong()

/** Initials in small circles: who a vault is shared with. */
@Composable
fun Avatars(names: List<String>) {
    Row(horizontalArrangement = Arrangement.spacedBy((-6).dp)) {
        names.take(4).forEach { n ->
            Box(Modifier.size(24.dp).clip(CircleShape).background(P.code).border(2.dp, P.surface, CircleShape), contentAlignment = Alignment.Center) {
                Text(n.take(1).uppercase(), style = MaterialTheme.typography.labelSmall, color = P.muted)
            }
        }
        if (names.size > 4) Text("+${names.size - 4}", style = MaterialTheme.typography.labelSmall, color = P.muted, modifier = Modifier.padding(start = 10.dp))
    }
}

@Composable
fun VaultsScreen() {
    val model = LocalContext.current.model
    var creating by remember { mutableStateOf<String?>(null) }
    var name by remember { mutableStateOf("") }
    Screen("Vaults and sharing", onBack = { model.pop() }) { m ->
        LazyColumn(m) {
            model.accounts.forEach { a ->
                item { SectionTitle(if (model.accounts.size > 1) accountLabel(a.server, a.username) else "Vaults") }
                items(model.vaults.filter { it.accountId == a.id }, key = { it.key }) { v ->
                    Row(
                        Modifier.fillMaxWidth().clickable { model.push(Route.Vault(v.accountId, v.id)) }.heightIn(min = 64.dp).padding(horizontal = 16.dp),
                        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Icon(if (v.members.size > 1) Icons.Rounded.Group else Icons.Rounded.Lock, null, tint = P.accent)
                        Column(Modifier.weight(1f)) {
                            Text(v.name.ifEmpty { "Untitled vault" }, color = P.fg)
                            Text("${v.itemCount} ${if (v.itemCount == 1u) "item" else "items"} · ${roleName(v.role)}", color = P.muted, style = MaterialTheme.typography.bodySmall)
                        }
                        if (v.members.size > 1) Avatars(v.members)
                    }
                }
                item {
                    TextButton(onClick = { creating = a.id; name = "" }, modifier = Modifier.padding(horizontal = 8.dp)) {
                        Icon(Icons.Rounded.Add, null); Spacer(Modifier.size(6.dp)); Text("New vault")
                    }
                }
            }
        }
    }
    creating?.let { acct ->
        AlertDialog(
            onDismissRequest = { creating = null },
            title = { Text("New vault") },
            text = { Field("Name", name, { name = it }) },
            confirmButton = {
                TextButton(enabled = name.isNotBlank(), onClick = {
                    creating = null
                    val n = name
                    model.act { model.call { it.createVault(acct, n) }; model.reload() }
                }) { Text("Create") }
            },
            dismissButton = { TextButton(onClick = { creating = null }) { Text("Cancel") } },
        )
    }
}

@Composable
fun VaultScreen(account: String, id: String) {
    val model = LocalContext.current.model
    val v = model.vault(account, id)
    var members by remember { mutableStateOf<List<MemberInfo>>(emptyList()) }
    var audit by remember { mutableStateOf<List<AuditData>>(emptyList()) }
    var sharing by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf(false) }
    var name by remember { mutableStateOf(v?.name ?: "") }
    var removing by remember { mutableStateOf<MemberInfo?>(null) }
    var busy by remember { mutableStateOf(false) }
    val owner = v?.role == Role.OWNER
    suspend fun load() {
        members = runCatching { model.call { it.members(account, id) } }.getOrElse { model.show(it); emptyList() }
        if (owner) audit = runCatching { model.call { it.audit(account, id) } }.getOrDefault(emptyList())
    }
    LaunchedEffect(account, id, model.vaults) { load() }
    if (v == null) { model.pop(); return }
    Screen(
        v.name.ifEmpty { "Vault" }, onBack = { model.pop() },
        actions = { if (owner) TextButton(onClick = { renaming = true; name = v.name }) { Text("Rename") } },
    ) { m ->
        Column(m.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (owner) PrimaryButton("Share vault", { sharing = true })
            if (busy) Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp); Text("Replacing the vault key…", color = P.muted)
            }
            Text("Members", color = P.muted, style = MaterialTheme.typography.labelLarge)
            Group {
                members.forEach { mem ->
                    Row(Modifier.fillMaxWidth().heightIn(min = 60.dp).padding(start = 12.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(mem.username + if (mem.isMe) " (you)" else "", color = P.fg, fontWeight = FontWeight.Medium)
                                if (mem.verified && !mem.isMe) Icon(Icons.Rounded.Verified, "Verified", tint = P.accent, modifier = Modifier.size(16.dp))
                            }
                            Text(roleName(mem.role) + (mem.expires?.let { ", until ${dayText(it.toLong())}" } ?: ""), color = P.muted, style = MaterialTheme.typography.bodySmall)
                            if (!mem.verified && !mem.isMe) Text("Not verified yet", color = P.warn, style = MaterialTheme.typography.bodySmall)
                        }
                        if (!mem.isMe) {
                            if (!mem.verified) TextButton(onClick = { model.push(Route.Verify(account, mem.username)) }) { Text("Verify") }
                            if (owner) TextButton(onClick = { removing = mem }) { Text("Remove", color = P.danger) }
                        }
                    }
                }
            }
            if (owner && audit.isNotEmpty()) {
                Text("Activity", color = P.muted, style = MaterialTheme.typography.labelLarge)
                Group {
                    audit.take(50).forEach { e ->
                        Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
                            Text("${e.username} ${e.action.replace('_', ' ')}", color = P.fg)
                            Text(dateText(e.ts.toLong() * 1000), color = P.muted, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
    if (sharing) ShareVaultSheet(account, id) { sharing = false }
    if (renaming) AlertDialog(
        onDismissRequest = { renaming = false },
        title = { Text("Rename vault") },
        text = { Field("Name", name, { name = it }) },
        confirmButton = {
            TextButton(enabled = name.isNotBlank(), onClick = {
                renaming = false
                val n = name
                model.act { model.call { it.renameVault(account, id, n) }; model.reload() }
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = { renaming = false }) { Text("Cancel") } },
    )
    removing?.let { mem ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text("Remove ${mem.username}?") },
            text = { Text("The vault gets a new key, so they can't open anything added from now on. Anything they already saw may still be on their devices.") },
            confirmButton = {
                TextButton(onClick = {
                    removing = null
                    busy = true
                    model.act {
                        try {
                            model.call { it.revoke(account, id, mem.username) }
                            model.reload()
                            load()
                            model.flash("Removed ${mem.username}")
                        } finally { busy = false }
                    }
                }) { Text("Remove from vault", color = P.danger) }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("Cancel") } },
        )
    }
}

/** Find a person by exact username, pick a role and expiry. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ShareVaultSheet(account: String, vault: String, onDismiss: () -> Unit) {
    val model = LocalContext.current.model
    var username by remember { mutableStateOf("") }
    var found by remember { mutableStateOf<Pair<String, Boolean>?>(null) }
    var role by remember { mutableStateOf(Role.READER) }
    var expiry by remember { mutableStateOf(0L) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val people = remember { mutableStateOf<List<uniffi.plaintext_ffi.UserData>>(emptyList()) }
    LaunchedEffect(Unit) { people.value = runCatching { model.call { it.users(account) } }.getOrDefault(emptyList()).filter { !it.disabled && it.username != model.account(account)?.username } }
    fun find(u: String) {
        error = null
        model.act {
            try {
                model.call { it.fingerprint(account, u) }
                found = u to model.call { it.isVerified(account, u) }
            } catch (e: Exception) { error = errorText(e); found = null }
        }
    }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = P.bg) {
        Column(Modifier.navigationBarsPadding().padding(horizontal = 20.dp).padding(bottom = 20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("Share vault", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = P.fg)
            Field("Their username", username, { username = it.lowercase(); found = null }, kind = Input.Username, onDone = { find(username.trim()) },
                trailing = { TextButton(onClick = { find(username.trim()) }, enabled = username.isNotBlank()) { Text("Find") } })
            if (people.value.isNotEmpty() && found == null) {
                Text("Everyone on this server", color = P.muted, style = MaterialTheme.typography.labelLarge)
                people.value.take(30).forEach { u ->
                    Row(Modifier.fillMaxWidth().clickable { username = u.username; find(u.username) }.heightIn(min = 44.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(u.username, color = P.fg, modifier = Modifier.weight(1f))
                        if (u.verified) Icon(Icons.Rounded.Verified, "Verified", tint = P.accent, modifier = Modifier.size(16.dp))
                    }
                }
            }
            found?.let { (u, verified) ->
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(u, color = P.fg, fontWeight = FontWeight.SemiBold)
                    if (verified) Icon(Icons.Rounded.Verified, "Verified", tint = P.accent, modifier = Modifier.size(16.dp))
                    else Text("Not verified yet", color = P.warn, style = MaterialTheme.typography.bodySmall)
                }
                Text("Role", color = P.muted, style = MaterialTheme.typography.labelLarge)
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    listOf(Role.READER, Role.WRITER, Role.OWNER).forEachIndexed { i, r ->
                        SegmentedButton(role == r, { role = r }, SegmentedButtonDefaults.itemShape(i, 3)) { Text(roleName(r)) }
                    }
                }
                Text("Expires", color = P.muted, style = MaterialTheme.typography.labelLarge)
                ExpiryPicker(expiry) { expiry = it }
                PrimaryButton("Share", {
                    busy = true
                    model.act {
                        try {
                            model.call { it.shareVault(account, vault, u, role, expiresAt(expiry)) }
                            model.reload()
                            model.flash("Shared with $u")
                            onDismiss()
                        } catch (e: Exception) { error = errorText(e) } finally { busy = false }
                    }
                }, busy = busy)
            }
            ErrorNote(error)
        }
    }
}

@Composable
fun ExpiryPicker(value: Long, options: List<Pair<Long, String>> = expiries, onChange: (Long) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        SecondaryButton(options.firstOrNull { it.first == value }?.second ?: "", { open = true })
        DropdownMenu(open, { open = false }) {
            options.forEach { (s, label) -> DropdownMenuItem({ Text(label) }, { onChange(s); open = false }) }
        }
    }
}

/**
 * Both fingerprints in large monospace plus a QR to scan. Scanning their code checks it against the keys pinned
 * for them; "The numbers match" is the in-person comparison. Never from a link (audit finding 2).
 */
@Composable
fun VerifyScreen(account: String, username: String) {
    val model = LocalContext.current.model
    var theirs by remember { mutableStateOf<String?>(null) }
    var mine by remember { mutableStateOf<String?>(null) }
    var code by remember { mutableStateOf<String?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(account, username) {
        try {
            theirs = model.call { it.fingerprint(account, username) }
            mine = model.account(account)?.fingerprint
            code = model.call { it.myVerifyCode(account) }
        } catch (e: Exception) { error = errorText(e) }
    }
    fun verified() { model.flash("$username is verified"); model.reload(); model.pop() }
    if (scanning) {
        Screen("Scan their code", onBack = { scanning = false }, close = true) { m ->
            Column(m) {
                Scanner("Ask $username to open Verify on their device.") { c ->
                    scanning = false
                    model.act {
                        val who = model.call { it.verifyScanned(account, c) }
                        if (who == username) verified() else { model.reload(); model.flash("$who is verified") }
                    }
                    null
                }
            }
        }
        return
    }
    Screen("Verify $username", onBack = { model.pop() }) { m ->
        Column(m.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("This makes sure your server can't swap their key for its own. Compare the numbers in person or on a call, or scan each other's code.", color = P.muted)
            theirs?.let {
                Text("$username's fingerprint", color = P.muted, style = MaterialTheme.typography.labelLarge)
                CodeBlock(it, style = MaterialTheme.typography.titleLarge)
            }
            mine?.let {
                Text("Your fingerprint", color = P.muted, style = MaterialTheme.typography.labelLarge)
                CodeBlock(it, style = MaterialTheme.typography.titleMedium)
            }
            code?.let {
                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    QrImage(it, 200.dp, "Your verification code")
                    Text("Let $username scan this.", color = P.muted)
                }
            }
            ErrorNote(error)
            PrimaryButton("Scan their code", { scanning = true })
            if (theirs != null) SecondaryButton("The numbers match", {
                model.act { model.call { it.markVerified(account, username) }; verified() }
            })
        }
    }
}

/** Send to a person (sealed to their key) or create a link, then the system share sheet. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareItemSheet(ref: ItemRef, title: String, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val model = context.model
    var mode by remember { mutableStateOf(0) }
    var to by remember { mutableStateOf("") }
    var expiry by remember { mutableStateOf(0L) }
    var linkExpiry by remember { mutableStateOf(86_400L) }
    var oneView by remember { mutableStateOf(false) }
    var link by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = P.bg) {
        Column(Modifier.navigationBarsPadding().padding(horizontal = 20.dp).padding(bottom = 20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("Share $title", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = P.fg)
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(mode == 0, { mode = 0 }, SegmentedButtonDefaults.itemShape(0, 2)) { Text("Send to a person") }
                SegmentedButton(mode == 1, { mode = 1 }, SegmentedButtonDefaults.itemShape(1, 2)) { Text("Create a link") }
            }
            if (mode == 0) {
                Text("It lands in their Inbox, encrypted to their key. Attachments stay in your vault.", color = P.muted)
                Field("Their username", to, { to = it.lowercase() }, kind = Input.Username)
                Text("Expires", color = P.muted, style = MaterialTheme.typography.labelLarge)
                ExpiryPicker(expiry) { expiry = it }
                PrimaryButton("Send", {
                    busy = true
                    error = null
                    val u = to.trim()
                    model.act {
                        try {
                            model.call { it.fingerprint(ref.account, u) } // pins them on first sight
                            model.call { it.sendItem(ref.account, ref.vault, ref.item, u, expiresAt(expiry)) }
                            model.flash("Sent to $u")
                            onDismiss()
                        } catch (e: Exception) { error = errorText(e) } finally { busy = false }
                    }
                }, enabled = to.isNotBlank(), busy = busy)
            } else if (link == null) {
                Text("Anyone with this link can see this item until it expires. The key is in the link itself, so the server can't read it.", color = P.muted)
                Text("Expires", color = P.muted, style = MaterialTheme.typography.labelLarge)
                ExpiryPicker(linkExpiry, listOf(3_600L to "In an hour", 86_400L to "In a day", 604_800L to "In a week", 2_592_000L to "In 30 days")) { linkExpiry = it }
                Row(verticalAlignment = Alignment.CenterVertically) { Text("Only one view", Modifier.weight(1f), color = P.fg); Switch(oneView, { oneView = it }) }
                PrimaryButton("Create a link", {
                    busy = true
                    error = null
                    model.act {
                        try {
                            link = model.call { it.createLink(ref.account, ref.vault, ref.item, model.vault.linkPage, linkExpiry.toULong(), oneView) }
                        } catch (e: Exception) { error = errorText(e) } finally { busy = false }
                    }
                }, busy = busy)
            } else {
                Text("Anyone with this link can see this item until it expires.", color = P.muted)
                CodeBlock(link!!, style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    SecondaryButton("Copy link", { model.copy(link!!, "Link") }, Modifier.weight(1f))
                    PrimaryButton("Share…", {
                        model.external = true
                        context.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, link), null))
                    }, Modifier.weight(1f))
                }
            }
            ErrorNote(error)
        }
    }
}
