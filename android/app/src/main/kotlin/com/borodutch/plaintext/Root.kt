package com.borodutch.plaintext

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Inbox
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import uniffi.plaintext_ffi.UnsentChanges

@Composable
fun Root() {
    val model = LocalContext.current.model
    Box(Modifier.fillMaxSize().background(P.bg)) {
        when {
            model.known.isEmpty() || model.onboarding -> Onboarding()
            model.locked -> UnlockScreen()
            else -> Main()
        }
        Banner()
        ToastBar()
    }
}

@Composable
private fun Main() {
    val model = LocalContext.current.model
    val top = model.stack.lastOrNull()
    BackHandler(enabled = top != null || model.tab != Tab.Items) {
        if (top != null) model.pop() else model.tab = Tab.Items
    }
    if (top != null) {
        when (top) {
            is Route.Item -> ItemDetail(top.ref)
            is Route.Edit -> ItemEditor(top)
            Route.Vaults -> VaultsScreen()
            is Route.Vault -> VaultScreen(top.account, top.id)
            is Route.Verify -> VerifyScreen(top.account, top.username)
            Route.Agents -> AgentsScreen()
            Route.Import -> ImportScreen()
            is Route.AddDevice -> AddDeviceScreen(top.account)
            is Route.Account -> AccountScreen(top.account)
            Route.Security -> SecurityScreen()
            Route.AddAccount -> Onboarding(adding = true, onClose = { model.pop() })
            is Route.People -> PeopleScreen(top.account)
        }
        return
    }
    Scaffold(
        containerColor = P.bg,
        bottomBar = {
            NavigationBar(containerColor = P.surface) {
                val colors = NavigationBarItemDefaults.colors(selectedIconColor = P.accent, selectedTextColor = P.accent, indicatorColor = P.code)
                NavigationBarItem(model.tab == Tab.Items, { model.tab = Tab.Items }, { Icon(Icons.Rounded.Key, null) }, label = { Text("Items") }, colors = colors)
                NavigationBarItem(model.tab == Tab.Watchtower, { model.tab = Tab.Watchtower }, {
                    BadgedBox(badge = { if (model.watch.isNotEmpty()) Badge { Text("${model.watch.size}") } }) { Icon(Icons.Rounded.Visibility, null) }
                }, label = { Text("Watchtower") }, colors = colors)
                NavigationBarItem(model.tab == Tab.Inbox, { model.tab = Tab.Inbox }, {
                    BadgedBox(badge = { if (model.inboxCount > 0) Badge { Text("${model.inboxCount}") } }) { Icon(Icons.Rounded.Inbox, null) }
                }, label = { Text("Inbox") }, colors = colors)
                NavigationBarItem(model.tab == Tab.Settings, { model.tab = Tab.Settings }, { Icon(Icons.Rounded.Settings, null) }, label = { Text("Settings") }, colors = colors)
            }
        },
    ) { pad ->
        Box(Modifier.padding(bottom = pad.calculateBottomPadding()).fillMaxSize()) {
            when (model.tab) {
                Tab.Items -> ItemsScreen()
                Tab.Watchtower -> WatchtowerScreen()
                Tab.Inbox -> InboxScreen()
                Tab.Settings -> SettingsScreen()
            }
        }
    }
}

/** Errors, at the top until dismissed. */
@Composable
private fun Banner() {
    val model = LocalContext.current.model
    val text = model.banner
    AnimatedVisibility(text != null, enter = fadeIn(), exit = fadeOut(), modifier = Modifier.statusBarsPadding().padding(12.dp)) {
        Row(
            Modifier.widthIn(max = 560.dp).fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(P.surface)
                .semantics { liveRegion = LiveRegionMode.Polite }.padding(start = 14.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(Icons.Rounded.ErrorOutline, null, tint = P.danger)
            Text(text ?: "", color = P.fg, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f).padding(vertical = 12.dp))
            model.bannerUnsent?.takeIf { it.text == text }?.let { u -> TextButton(onClick = { model.review(u) }) { Text("Review…", color = P.accent) } }
            IconButton(onClick = { model.banner = null }) { Icon(Icons.Rounded.Close, "Dismiss", tint = P.muted) }
        }
    }
    model.reviewing?.let { r ->
        AlertDialog(
            onDismissRequest = { model.reviewing = null },
            title = { Text("Drop changes to ${r.changes.name}?") },
            text = { Text(unsentSummary(r.changes)) },
            confirmButton = { TextButton(onClick = { model.discard(r) }) { Text("Drop changes", color = P.danger) } },
            dismissButton = { TextButton(onClick = { model.reviewing = null }) { Text("Cancel") } },
        )
    }
}

private fun unsentSummary(c: UnsentChanges): String {
    val lines = mutableListOf("You can only read ${c.name} now, so these changes on this device can't be sent:")
    if (c.changed.isNotEmpty()) {
        val more = if (c.changed.size > 8) " and ${c.changed.size - 8} more" else ""
        lines += "Added or edited: ${c.changed.take(8).joinToString(", ")}$more"
    }
    val deleted = c.deleted.toInt()
    if (deleted > 0) lines += if (deleted == 1) "1 item deleted" else "$deleted items deleted"
    if (c.renamed) lines += "The vault's name or description changed"
    if (lines.size == 1) lines[0] = lines[0].dropLast(1) + "."
    lines += "Dropping them downloads the vault again from the server. Copy out anything you want to keep first."
    return lines.joinToString("\n")
}

/** Short confirmations ("Password copied"), with Undo where it applies. */
@Composable
private fun ToastBar() {
    val model = LocalContext.current.model
    val t = model.toast
    LaunchedEffect(t?.id) {
        if (t != null) {
            delay(if (t.undo != null) 5_000 else 2_500)
            if (model.toast?.id == t.id) model.toast = null
        }
    }
    Box(Modifier.fillMaxSize().navigationBarsPadding().padding(bottom = 88.dp), contentAlignment = Alignment.BottomCenter) {
        AnimatedVisibility(t != null, enter = fadeIn(), exit = fadeOut()) {
            Row(
                Modifier.padding(horizontal = 16.dp).clip(RoundedCornerShape(12.dp)).background(P.fg)
                    .semantics { liveRegion = LiveRegionMode.Polite }.clickable { model.toast = null }
                    .padding(start = 16.dp, end = if (t?.undo != null) 4.dp else 16.dp, top = 6.dp, bottom = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(t?.text ?: "", color = P.bg, modifier = Modifier.padding(vertical = 8.dp))
                t?.undo?.let { undo -> TextButton(onClick = { undo(); model.toast = null }) { Text("Undo", color = P.bg, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold) } }
            }
        }
    }
}
