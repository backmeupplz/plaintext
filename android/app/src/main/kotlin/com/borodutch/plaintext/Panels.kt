package com.borodutch.plaintext

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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Inbox
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
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
import uniffi.plaintext_ffi.AgentInfo
import uniffi.plaintext_ffi.Finding
import uniffi.plaintext_ffi.InboxContent
import uniffi.plaintext_ffi.InboxEntry
import uniffi.plaintext_ffi.Recipe
import uniffi.plaintext_ffi.Role
import uniffi.plaintext_ffi.WatchItem
import uniffi.plaintext_ffi.generatePassword
import uniffi.plaintext_ffi.validUsername

/** A tab's title bar. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TabTitle(title: String) {
    TopAppBar(title = { Text(title, fontWeight = FontWeight.SemiBold) }, colors = TopAppBarDefaults.topAppBarColors(containerColor = P.bg, titleContentColor = P.fg))
}

// ---------- Inbox ----------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InboxScreen() {
    val model = LocalContext.current.model
    Column(Modifier.fillMaxSize()) {
        TabTitle("Inbox")
        PullToRefreshBox(isRefreshing = model.syncing, onRefresh = { model.syncAll() }, modifier = Modifier.fillMaxSize()) {
            val empty = model.accounts.all { model.inbox[it.id].isNullOrEmpty() }
            if (empty) {
                Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.Center) {
                    EmptyState(Icons.Rounded.Inbox, "Items people send you and your agents' requests show up here.")
                }
            } else {
                LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    model.accounts.forEach { a ->
                        val entries = model.inbox[a.id].orEmpty()
                        if (entries.isEmpty()) return@forEach
                        if (model.accounts.size > 1) item { SectionTitle(accountLabel(a.server, a.username)) }
                        items(entries) { e -> InboxRow(a.id, e) }
                    }
                }
            }
        }
    }
}

@Composable
private fun InboxRow(account: String, e: InboxEntry) {
    val model = LocalContext.current.model
    var saveMenu by remember { mutableStateOf(false) }
    var grant by remember { mutableStateOf(false) }
    var picking by remember { mutableStateOf(false) }
    // "Your agent" only when the agent is also verified: the server alone could claim an agent is yours (audit finding 11).
    val myAgent = e.fromAgentOfMine && e.verified
    fun dismiss() = model.act { model.call { it.dismissMessage(account, e.id) }; model.syncAll() }
    Card {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Icon(if (myAgent) Icons.Rounded.Memory else Icons.Rounded.Person, null, tint = P.muted, modifier = Modifier.size(18.dp))
                Text(e.from, color = P.fg, fontWeight = FontWeight.SemiBold)
                if (e.verified) Icon(Icons.Rounded.Verified, "Verified", tint = P.accent, modifier = Modifier.size(16.dp))
                else Text("not verified", color = P.warn, style = MaterialTheme.typography.bodySmall)
                if (myAgent) Text("your agent", color = P.muted, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.weight(1f))
                e.expires?.let { Text("until ${dayText(it.toLong())}", color = P.muted, style = MaterialTheme.typography.bodySmall) }
            }
            when (val c = e.content) {
                is InboxContent.Item -> {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Monogram(c.item.title, 36)
                        Column { Text(c.item.title.ifEmpty { "Untitled" }, color = P.fg); Text(kindName(c.item.kind), color = P.muted, style = MaterialTheme.typography.bodySmall) }
                    }
                    Row {
                        Box {
                            TextButton(onClick = { saveMenu = true }) { Text("Save to vault") }
                            DropdownMenu(saveMenu, { saveMenu = false }) {
                                model.vaults.filter { it.accountId == account && it.role != null && it.role != Role.READER }.forEach { v ->
                                    DropdownMenuItem({ Text(v.name) }, {
                                        saveMenu = false
                                        model.act { model.call { it.saveFromInbox(account, e.id, v.id) }; model.syncAll(); model.flash("Saved") }
                                    })
                                }
                            }
                        }
                        Spacer(Modifier.weight(1f))
                        TextButton(onClick = ::dismiss) { Text("Dismiss", color = P.danger) }
                    }
                }
                is InboxContent.Request -> {
                    Text(c.text, color = P.fg)
                    FlowRow {
                        TextButton(onClick = { grant = true }) { Text("Give access to a vault…") }
                        TextButton(onClick = { picking = true }) { Text("Send an item…") }
                        TextButton(onClick = ::dismiss) { Text("Dismiss", color = P.danger) }
                    }
                }
                is InboxContent.Unreadable -> Note(c.reason)
            }
        }
    }
    if (grant) AlertDialog(
        onDismissRequest = { grant = false },
        title = { Text("Give ${e.from} access to") },
        text = {
            Column {
                model.vaults.filter { it.accountId == account && it.role == Role.OWNER }.forEach { v ->
                    Text("${v.name} (can view)", color = P.fg, modifier = Modifier.fillMaxWidth().clickable {
                        grant = false
                        model.act {
                            model.call { it.shareVault(account, v.id, e.from, Role.READER, null) }
                            model.call { it.dismissMessage(account, e.id) }
                            model.syncAll()
                            model.flash("${e.from} can view it now")
                        }
                    }.padding(vertical = 14.dp))
                }
            }
        },
        confirmButton = { TextButton(onClick = { grant = false }) { Text("Cancel") } },
    )
    if (picking) PickItemSheet(account, e.from) { picking = false }
}

/** Pick one item of an account to send someone. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PickItemSheet(account: String, to: String, onDismiss: () -> Unit) {
    val model = LocalContext.current.model
    var query by remember { mutableStateOf("") }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = P.bg) {
        Column(Modifier.navigationBarsPadding()) {
            Text("Send to $to", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = P.fg, modifier = Modifier.padding(horizontal = 20.dp))
            Field("Search", query, { query = it }, modifier = Modifier.padding(16.dp))
            LazyColumn {
                items(model.core.items(account, null, query, false), key = { it.ref.key }) { s ->
                    ItemRow(s) {
                        model.act {
                            model.call { it.sendItem(account, s.vaultId, s.id, to, null) }
                            model.flash("Sent ${s.title} to $to")
                            onDismiss()
                        }
                    }
                }
            }
        }
    }
}

// ---------- Agents ----------

@Composable
fun AgentsScreen() {
    val model = LocalContext.current.model
    var agents by remember { mutableStateOf(mapOf<String, List<AgentInfo>>()) }
    var creating by remember { mutableStateOf<String?>(null) }
    var disabling by remember { mutableStateOf<Pair<String, String>?>(null) }
    suspend fun load() {
        agents = model.accounts.associate { a -> a.id to runCatching { model.call { it.agents(a.id) } }.getOrElse { model.show(it); emptyList() } }
    }
    LaunchedEffect(Unit) { load() }
    Screen("Agents", onBack = { model.pop() }) { m ->
        LazyColumn(m.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item { Text("An agent is an account for a script or an AI assistant. It reaches only the vaults you give it, and asks you here when it needs more.", color = P.muted) }
            model.accounts.forEach { a ->
                item { SectionTitle(if (model.accounts.size > 1) accountLabel(a.server, a.username) else "Your agents") }
                items(agents[a.id].orEmpty(), key = { a.id + it.name }) { ag ->
                    Card {
                        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Rounded.Memory, null, tint = P.accent, modifier = Modifier.size(20.dp))
                                Spacer(Modifier.size(8.dp))
                                Text(ag.name, color = P.fg, fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
                                Switch(!ag.disabled, { if (!it) disabling = a.id to ag.name }, enabled = !ag.disabled)
                            }
                            ag.access.forEach { x -> Text("${x.vaultName}: ${roleName(x.role).lowercase()}${x.expires?.let { ", until ${dayText(it.toLong())}" } ?: ""}", color = P.muted, style = MaterialTheme.typography.bodyMedium) }
                            Text(ag.lastActive?.let { "Last active ${dateText(it.toLong() * 1000)}" } ?: "Not used yet", color = P.muted, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
                item { TextButton(onClick = { creating = a.id }) { Icon(Icons.Rounded.Add, null); Spacer(Modifier.size(6.dp)); Text("New agent") } }
            }
        }
    }
    creating?.let { acct -> NewAgentSheet(acct) { creating = null; model.act { load() } } }
    disabling?.let { (acct, name) ->
        AlertDialog(
            onDismissRequest = { disabling = null },
            title = { Text("Turn off $name?") },
            text = { Text("Its key stops working everywhere. This can't be undone; make a new agent if you need one again.") },
            confirmButton = { TextButton(onClick = { disabling = null; model.act { model.call { it.disableUser(acct, name) }; load() } }) { Text("Turn off", color = P.danger) } },
            dismissButton = { TextButton(onClick = { disabling = null }) { Text("Cancel") } },
        )
    }
}

/** Name → vault and role → expiry → the key, shown once. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NewAgentSheet(account: String, onDismiss: () -> Unit) {
    val model = LocalContext.current.model
    val owned = model.vaults.filter { it.accountId == account && it.role == Role.OWNER }
    var name by remember { mutableStateOf("") }
    var vault by remember { mutableStateOf(owned.firstOrNull { !it.isDefault }?.id ?: owned.firstOrNull()?.id ?: "") }
    var role by remember { mutableStateOf(Role.READER) }
    var expiry by remember { mutableStateOf(0L) }
    var key by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var vaultMenu by remember { mutableStateOf(false) }
    val server = model.account(account)?.server ?: ""
    ModalBottomSheet(onDismissRequest = { if (key == null) onDismiss() }, containerColor = P.bg) {
        Column(Modifier.navigationBarsPadding().padding(horizontal = 20.dp).padding(bottom = 20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("New agent", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = P.fg)
            val k = key
            if (k != null) {
                Text("Agent key", color = P.muted, style = MaterialTheme.typography.labelLarge)
                CodeBlock(k, style = MaterialTheme.typography.bodyMedium)
                SecondaryButton("Copy", { model.copy(k, "Agent key") })
                Text("This is the only time it's shown. Store it where the agent runs; anyone with it acts as ${name.lowercase()}.", color = P.muted, style = MaterialTheme.typography.bodySmall)
                Text("Use it", color = P.muted, style = MaterialTheme.typography.labelLarge)
                CodeBlock("PLAINTEXT_SERVER=$server PLAINTEXT_AGENT_KEY=… plaintext run --env API_TOKEN=\"Item/password\" -- ./deploy.sh", style = MaterialTheme.typography.bodySmall)
                Text("For an AI assistant, add the MCP server: command plaintext, argument mcp, with the same two variables.", color = P.muted, style = MaterialTheme.typography.bodySmall)
                PrimaryButton("Done", onDismiss)
            } else {
                Field("Name", name, { name = it.lowercase() }, kind = Input.Username, placeholder = "deploy-bot")
                Text("Vault", color = P.muted, style = MaterialTheme.typography.labelLarge)
                Box {
                    SecondaryButton(owned.firstOrNull { it.id == vault }?.name ?: "Choose a vault", { vaultMenu = true })
                    DropdownMenu(vaultMenu, { vaultMenu = false }) { owned.forEach { v -> DropdownMenuItem({ Text(v.name) }, { vault = v.id; vaultMenu = false }) } }
                }
                Text("Role", color = P.muted, style = MaterialTheme.typography.labelLarge)
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    listOf(Role.READER, Role.WRITER).forEachIndexed { i, r -> SegmentedButton(role == r, { role = r }, SegmentedButtonDefaults.itemShape(i, 2)) { Text(roleName(r)) } }
                }
                Text("Expires", color = P.muted, style = MaterialTheme.typography.labelLarge)
                ExpiryPicker(expiry) { expiry = it }
                ErrorNote(error)
                PrimaryButton("Create", {
                    busy = true
                    error = null
                    val (n, v, r) = Triple(name, vault, role)
                    model.act {
                        try {
                            key = model.call { it.createAgent(account, n, v, r, expiresAt(expiry)) }
                            model.reload()
                        } catch (e: Exception) { error = errorText(e) } finally { busy = false }
                    }
                }, enabled = validUsername(name) && vault.isNotEmpty(), busy = busy)
            }
        }
    }
}

// ---------- Watchtower ----------

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun WatchtowerScreen() {
    val context = LocalContext.current
    val model = context.model
    var breachCheck by remember { mutableStateOf(model.vault.breachCheck) }
    var checking by remember { mutableStateOf(false) }
    fun items(f: Finding) = model.watch.filter { f in it.findings }
    val breached = model.core.items(null, null, "", false).filter { model.breached[it.ref.key] != null }
    fun check() { checking = true; model.act { try { model.runBreachCheck() } finally { checking = false } } }
    LaunchedEffect(Unit) { if (breachCheck && model.breached.isEmpty()) check() }
    fun fix(w: WatchItem) {
        val ref = ItemRef(w.accountId, w.vaultId, w.id)
        val data = runCatching { model.core.item(ref.account, ref.vault, ref.item) }.getOrNull() ?: return
        data.password = generatePassword(Recipe.Random(20u, true, true))
        data.urls.firstOrNull()?.let { openUrl(context, it) }
        model.push(Route.Edit(ref.account, ref.vault, ref.item, data))
    }
    Column(Modifier.fillMaxSize()) {
        TabTitle("Watchtower")
        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), maxItemsInEachRow = 3) {
                    Stat("Weak", items(Finding.WEAK).size, Modifier.weight(1f))
                    Stat("Reused", items(Finding.REUSED).size, Modifier.weight(1f))
                    Stat("Breached", if (breachCheck) breached.size else null, Modifier.weight(1f))
                    Stat("Unsecured", items(Finding.UNSECURED).size, Modifier.weight(1f))
                    Stat("No 2FA", items(Finding.NO_TWO_FACTOR).size, Modifier.weight(1f))
                }
            }
            item {
                Card {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("Check for breached passwords", color = P.fg, modifier = Modifier.weight(1f))
                            Switch(breachCheck, { on -> breachCheck = on; model.vault.breachCheck = on; if (on) check() else model.breached = emptyMap() })
                        }
                        if (checking) Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp); Text("Checking…", color = P.muted)
                        }
                        Text("Plaintext asks Have I Been Pwned about each password. Only the first 5 characters of its hash leave this device, never the password.", color = P.muted, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            val groups = listOf(
                "Breached" to breached.map { s -> WatchItem(s.accountId, s.vaultId, s.id, s.title, "Seen in ${model.breached[s.ref.key]} breaches", emptyList(), 0u) },
                "Weak passwords" to items(Finding.WEAK),
                "Reused passwords" to items(Finding.REUSED),
                "Unsecured websites" to items(Finding.UNSECURED),
                "Two-factor available" to items(Finding.NO_TWO_FACTOR),
            )
            groups.forEach { (title, list) ->
                if (list.isEmpty()) return@forEach
                item { SectionTitle(title) }
                items(list, key = { title + it.accountId + it.vaultId + it.id }) { w ->
                    Row(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(P.surface)
                            .clickable { model.push(Route.Item(ItemRef(w.accountId, w.vaultId, w.id))) }.heightIn(min = 60.dp).padding(horizontal = 12.dp),
                        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Monogram(w.title, 34)
                        Column(Modifier.weight(1f)) {
                            Text(w.title.ifEmpty { "Untitled" }, color = P.fg)
                            Text(if (w.reusedWith > 0u) "Used in ${w.reusedWith} other ${if (w.reusedWith == 1u) "item" else "items"}" else w.subtitle, color = P.muted, style = MaterialTheme.typography.bodySmall)
                        }
                        if (title != "Two-factor available" && title != "Unsecured websites") TextButton(onClick = { fix(w) }) { Text("Change") }
                    }
                }
            }
            if (model.watch.isEmpty() && breached.isEmpty()) item {
                Row(Modifier.padding(vertical = 16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Rounded.Shield, null, tint = P.accent); Text("Nothing to fix. Nice.", color = P.accent)
                }
            }
        }
    }
}

@Composable
private fun Stat(label: String, n: Int?, modifier: Modifier) {
    Column(
        modifier.widthIn(min = 96.dp).clip(RoundedCornerShape(12.dp)).background(P.surface).heightIn(min = 64.dp).padding(8.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center,
    ) {
        Text(n?.toString() ?: "–", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = if ((n ?: 0) > 0) P.warn else P.fg)
        Text(label, style = MaterialTheme.typography.labelMedium, color = P.muted)
    }
}
