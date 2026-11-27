package com.borodutch.plaintext

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Group
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.semantics.Role
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.plaintext_ffi.ImportFormat
import uniffi.plaintext_ffi.SessionData
import uniffi.plaintext_ffi.UserData
import uniffi.plaintext_ffi.defaultLinkPage
import uniffi.plaintext_ffi.passwordStrength
import uniffi.plaintext_ffi.serverInfo

/** A settings row: icon, title, optional detail, chevron. */
@Composable
fun NavRow(title: String, detail: String? = null, icon: ImageVector? = null, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).heightIn(min = 56.dp).padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (icon != null) Icon(icon, null, tint = P.accent)
        Column(Modifier.weight(1f).padding(vertical = 8.dp)) {
            Text(title, color = P.fg)
            if (detail != null) Text(detail, color = P.muted, style = MaterialTheme.typography.bodySmall)
        }
        Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, null, tint = P.muted)
    }
}

@Composable
fun SwitchRow(title: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).toggleable(checked, enabled = enabled, role = Role.Switch, onValueChange = onChange).padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, color = if (enabled) P.fg else P.muted, modifier = Modifier.weight(1f))
        Switch(checked, null, enabled = enabled)
    }
}

@Composable
fun ChoiceRow(title: String, value: Int, options: List<Pair<Int, String>>, onChange: (Int) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        Row(Modifier.fillMaxWidth().clickable { open = true }.heightIn(min = 56.dp).padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(title, color = P.fg, modifier = Modifier.weight(1f))
            Text(options.firstOrNull { it.first == value }?.second ?: "", color = P.muted)
        }
        DropdownMenu(open, { open = false }) { options.forEach { (v, l) -> DropdownMenuItem({ Text(l) }, { onChange(v); open = false }) } }
    }
}

@Composable
fun SettingsScreen() {
    val model = LocalContext.current.model
    Column(Modifier.fillMaxSize()) {
        TabTitle("Settings")
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Accounts", color = P.muted, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 8.dp))
            Group {
                model.known.forEach { k ->
                    val info = model.account(k.id)
                    NavRow(k.username, k.host + when { info == null -> " · Locked"; info.pending -> " · Changes waiting to sync"; else -> "" }, Icons.Rounded.Person) { model.push(Route.Account(k.id)) }
                }
                NavRow("Add account", icon = Icons.Rounded.Add) { model.push(Route.AddAccount) }
            }
            Group {
                NavRow("Security", "Auto-lock, biometrics, clipboard", Icons.Rounded.Security) { model.push(Route.Security) }
                NavRow("Vaults and sharing", icon = Icons.Rounded.Group) { model.push(Route.Vaults) }
                NavRow("Agents", icon = Icons.Rounded.Memory) { model.push(Route.Agents) }
                NavRow("Import from 1Password, Bitwarden or CSV", icon = Icons.Rounded.Download) { model.push(Route.Import) }
            }
            Group {
                var recent by remember { mutableStateOf(model.vault.sortRecent) }
                SwitchRow("Sort by recently changed", recent) { recent = it; model.vault.sortRecent = it; model.reload() }
            }
            Text("Share links", color = P.muted, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 8.dp))
            var page by remember { mutableStateOf(model.vault.linkPage.ifEmpty { defaultLinkPage() }) }
            Field("Link page", page, { page = it; model.vault.linkPage = it.trim() }, kind = Input.Url, mono = true,
                note = "The page that opens shared links. If you host your own copy, put its address here; never host it on your vault server.")
            if (page != defaultLinkPage()) TextButton(onClick = { page = defaultLinkPage(); model.vault.linkPage = "" }) { Text("Use getplaintext.org") }
            Text("About", color = P.muted, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 8.dp))
            val context = LocalContext.current
            Group {
                Row(Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("Version", color = P.fg, modifier = Modifier.weight(1f)); Text(BuildConfig.VERSION_NAME, color = P.muted)
                }
                NavRow("Source code") { openUrl(context, "https://github.com/backmeupplz/plaintext") }
                NavRow("getplaintext.org") { openUrl(context, "https://getplaintext.org") }
            }
            PrimaryButton("Lock now", { model.lock() }, icon = Icons.Rounded.Lock, modifier = Modifier.padding(vertical = 16.dp))
        }
    }
}

@Composable
fun SecurityScreen() {
    val context = LocalContext.current
    val model = context.model
    var autoLock by remember { mutableStateOf(model.vault.autoLockMinutes) }
    var clip by remember { mutableStateOf(model.vault.clipboardSeconds) }
    var bio by remember { mutableStateOf(model.vault.biometrics && Vault.biometricsAvailable(context)) }
    Screen("Security", onBack = { model.pop() }) { m ->
        Column(m.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Group {
                ChoiceRow("Auto-lock", autoLock, listOf(0 to "Immediately", 1 to "After 1 minute", 5 to "After 5 minutes", 10 to "After 10 minutes", 60 to "After 1 hour", 480 to "After 8 hours")) {
                    autoLock = it; model.vault.autoLockMinutes = it
                }
                SwitchRow("Unlock with fingerprint or face", bio, enabled = Vault.biometricsAvailable(context)) { on -> bio = on; model.biometricsChanged(on) }
                ChoiceRow("Clear copied secrets", clip, listOf(30 to "After 30 seconds", 90 to "After 90 seconds", 300 to "After 5 minutes")) {
                    clip = it; model.vault.clipboardSeconds = it
                }
            }
            Text(
                "Plaintext also locks when the screen turns off, and it never appears in screenshots, screen recordings or the recent apps view." +
                    (Vault.biometricsMissing(context)?.let { " $it" } ?: ""),
                color = P.muted, style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
fun AccountScreen(account: String) {
    val context = LocalContext.current
    val model = context.model
    val known = model.known(account) ?: run { model.pop(); return }
    val info = model.account(account)
    var sessions by remember { mutableStateOf<List<SessionData>>(emptyList()) }
    var open by remember { mutableStateOf(false) }
    var invite by remember { mutableStateOf<String?>(null) }
    var changing by remember { mutableStateOf(false) }
    var confirmSignOut by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val sk = remember(account) { model.vault.secretKey(account) }
    val saveKit = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        if (uri != null && sk != null) model.scope.launch {
            runCatching { EmergencyKit.save(context, uri, sk, known.server, known.username) }
                .onSuccess { model.flash("Emergency Kit saved") }.onFailure { model.banner = "Couldn't save the Emergency Kit there. Try another place." }
        }
    }
    suspend fun load() {
        if (model.account(account) == null) return
        open = runCatching { model.call { serverInfo(known.server) }.open }.getOrDefault(false)
        sessions = runCatching { model.call { it.sessions(account) } }.getOrDefault(emptyList())
    }
    LaunchedEffect(account, info != null) { load() }
    Screen(known.name, onBack = { model.pop() }) { m ->
        Column(m.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Group {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    LabeledValue("Username", known.username)
                    LabeledValue("Server", known.server)
                    if (info != null) LabeledValue("Your fingerprint", info.fingerprint)
                    if (info?.admin == true) Text("Server admin", color = P.muted)
                }
            }
            if (info == null) {
                Text("Locked", color = P.muted, style = MaterialTheme.typography.labelLarge)
                Field("Password", password, { password = it }, kind = Input.Password)
                PrimaryButton("Unlock", {
                    busy = true
                    val pw = password
                    model.act { try { model.unlock(known, pw); password = "" } finally { busy = false } }
                }, enabled = password.isNotEmpty(), busy = busy)
            } else {
                Group {
                    NavRow("Add a device", "Show a code your other device scans to sign in") { model.push(Route.AddDevice(account)) }
                    if (sk != null) {
                        NavRow("Save the Emergency Kit as PDF") { model.external = true; saveKit.launch("Plaintext Emergency Kit - ${known.username}.pdf") }
                        NavRow("Print the Emergency Kit") { EmergencyKit.print(context, sk, known.server, known.username) }
                    }
                    NavRow("Change password") { changing = true }
                    if (info.admin || open) NavRow("People", if (info.admin) "Invite and disable people" else "Invite someone") { model.push(Route.People(account)) }
                }
                Text("Devices", color = P.muted, style = MaterialTheme.typography.labelLarge)
                Group {
                    sessions.forEach { s ->
                        Row(Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(start = 12.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(s.device, color = P.fg)
                                Text(if (s.current) "This device" else "Since ${dayText(s.created.toLong())}", color = P.muted, style = MaterialTheme.typography.bodySmall)
                            }
                            if (!s.current) TextButton(onClick = { model.act { model.call { it.endSession(account, s.id) }; load() } }) { Text("Sign out", color = P.danger) }
                        }
                    }
                }
            }
            TextButton(onClick = { confirmSignOut = true }) { Text("Sign out of this account", color = P.danger) }
        }
    }
    if (changing) ChangePasswordDialog(known) { changing = false }
    if (confirmSignOut) AlertDialog(
        onDismissRequest = { confirmSignOut = false },
        title = { Text("Sign out of ${known.name}?") },
        text = { Text("This device forgets the account and its copies. You'll need your Emergency Kit to sign in again.") },
        confirmButton = {
            TextButton(onClick = {
                confirmSignOut = false
                model.pop()
                model.signOut(account)
            }) { Text("Sign out", color = P.danger) }
        },
        dismissButton = { TextButton(onClick = { confirmSignOut = false }) { Text("Cancel") } },
    )
}

@Composable
private fun ChangePasswordDialog(known: KnownAccount, onDismiss: () -> Unit) {
    val model = LocalContext.current.model
    var old by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Change password") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Field("Current password", old, { old = it }, kind = Input.Password)
                Field("New password", new, { new = it }, kind = Input.Password)
                StrengthMeter(new)
                Text("Your other devices sign in again with the new password. Your Secret Key stays the same.", color = P.muted, style = MaterialTheme.typography.bodySmall)
                ErrorNote(error)
            }
        },
        confirmButton = {
            TextButton(enabled = !busy && old.isNotEmpty() && passwordStrength(new).level >= 1u, onClick = {
                val sk = model.vault.secretKey(known.id) ?: run { error = "This device lost its copy of the Secret Key. Sign in again with your Emergency Kit."; return@TextButton }
                busy = true
                val (o, n) = old to new
                model.act {
                    try {
                        model.call { it.changePassword(known.id, sk, o, n) }
                        model.flash("Password changed")
                        onDismiss()
                    } catch (e: Exception) { error = errorText(e) } finally { busy = false }
                }
            }) { Text("Change") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/**
 * The sign-in QR (server, username and Secret Key) for another device. It shows only after a fresh biometric check
 * when the phone has one, and hides itself after a minute (audit finding 15). Screenshots are blocked app-wide.
 */
@Composable
fun AddDeviceScreen(account: String) {
    val context = LocalContext.current
    val model = context.model
    var code by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(code) { if (code != null) { delay(60_000); code = null } }
    fun show() {
        val sk = model.vault.secretKey(account) ?: run { model.banner = "This device lost its copy of the Secret Key. Sign in again with your Emergency Kit."; return }
        val reveal = { code = runCatching { model.core.addDeviceCode(account, sk) }.getOrElse { model.show(it); null } }
        if (Vault.canPrompt(context)) promptBiometrics(context as FragmentActivity, "Show the sign-in code") { reveal() } else reveal()
    }
    Screen("Add a device", onBack = { model.pop() }) { m ->
        Column(m.verticalScroll(rememberScrollState()).padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(20.dp)) {
            Text("On the new device, choose Sign in, then Scan from another device. This code holds your Secret Key, so only show it to your own devices.", color = P.muted)
            val c = code
            if (c != null) {
                QrImage(c, 260.dp, "Sign-in code")
                Text("It hides itself in a minute.", color = P.muted, style = MaterialTheme.typography.bodySmall)
            } else {
                PrimaryButton("Show the code", ::show)
            }
        }
    }
}

@Composable
fun PeopleScreen(account: String) {
    val context = LocalContext.current
    val model = context.model
    val info = model.account(account)
    var users by remember { mutableStateOf<List<UserData>>(emptyList()) }
    var invite by remember { mutableStateOf<String?>(null) }
    suspend fun load() { if (info?.admin == true) users = runCatching { model.call { it.users(account) } }.getOrDefault(emptyList()) }
    LaunchedEffect(account) { load() }
    Screen("People", onBack = { model.pop() }) { m ->
        Column(m.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            PrimaryButton("Invite someone", { model.act { invite = model.call { it.invite(account) } } })
            Text("An invite works once. It carries your fingerprint, so the person you invite and you are verified to each other.", color = P.muted, style = MaterialTheme.typography.bodySmall)
            invite?.let { inv ->
                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    QrImage(inv, 220.dp, "Invite code")
                    CodeBlock(inv, style = MaterialTheme.typography.bodySmall)
                    SecondaryButton("Share invite", {
                        model.external = true
                        context.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, inv), null))
                    })
                }
            }
            if (info?.admin == true) {
                Text("Everyone on this server", color = P.muted, style = MaterialTheme.typography.labelLarge)
                Group {
                    users.filter { it.username != info.username }.forEach { u ->
                        Row(Modifier.fillMaxWidth().heightIn(min = 52.dp).padding(start = 12.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(u.username, color = if (u.disabled) P.muted else P.fg)
                                if (u.isAgent) Text("agent of ${u.owner ?: ""}", color = P.muted, style = MaterialTheme.typography.bodySmall)
                            }
                            if (u.disabled) Text("Disabled", color = P.muted, modifier = Modifier.padding(end = 12.dp))
                            else TextButton(onClick = { model.act { model.call { it.disableUser(account, u.username) }; load() } }) { Text("Disable", color = P.danger) }
                        }
                    }
                }
            }
        }
    }
}

/** 1Password (.1pux), Bitwarden (.json) or CSV, parsed by the Rust importers. */
@Composable
fun ImportScreen() {
    val context = LocalContext.current
    val model = context.model
    var format by remember { mutableStateOf(ImportFormat.ONE_PUX) }
    var account by remember { mutableStateOf(model.accounts.firstOrNull()?.id ?: "") }
    var busy by remember { mutableStateOf(false) }
    var done by remember { mutableStateOf<Int?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        busy = true
        error = null
        val (f, a) = format to account
        model.act {
            try {
                val bytes = withContext(Dispatchers.IO) { context.contentResolver.openInputStream(uri)?.use { it.readBytes() } } ?: throw UserError("Couldn't read that file.")
                done = model.call { it.importItems(a, f, bytes, null) }.toInt()
                bytes.fill(0)
                model.reload()
            } catch (e: Exception) { error = errorText(e) } finally { busy = false }
        }
    }
    Screen("Import", onBack = { model.pop() }) { m ->
        Column(m.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("From", color = P.muted, style = MaterialTheme.typography.labelLarge)
            Group {
                ChoiceRow("Format", format.ordinal, listOf(0 to "1Password (.1pux)", 1 to "Bitwarden (.json)", 2 to "CSV (Chrome, Firefox, Safari, others)")) { format = ImportFormat.entries[it] }
                if (model.accounts.size > 1) {
                    ChoiceRow("Account", model.accounts.indexOfFirst { it.id == account }, model.accounts.mapIndexed { i, a -> i to accountLabel(a.server, a.username) }) { account = model.accounts[it].id }
                }
            }
            Text("Items go into vaults with the same names as in your old password manager.", color = P.muted, style = MaterialTheme.typography.bodySmall)
            Note("Export unencrypted from your old password manager, import here, then delete the export file.")
            PrimaryButton("Choose file…", { model.external = true; pick.launch(arrayOf("*/*")) }, busy = busy, enabled = account.isNotEmpty())
            done?.let { Text("Imported $it items.", color = P.accent, fontWeight = FontWeight.SemiBold) }
            ErrorNote(error)
            Spacer(Modifier.size(8.dp))
        }
    }
}
