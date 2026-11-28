package com.borodutch.plaintext

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountBalance
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Archive
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.CreditCard
import androidx.compose.material.icons.rounded.CurrencyBitcoin
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.DirectionsCar
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Password
import androidx.compose.material.icons.rounded.Group
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Star
import androidx.compose.material.icons.rounded.StickyNote2
import androidx.compose.material.icons.rounded.Storage
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material.icons.rounded.Api
import androidx.compose.material.icons.rounded.CardMembership
import androidx.compose.material.icons.rounded.FlightTakeoff
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import uniffi.plaintext_ffi.ItemSummary
import uniffi.plaintext_ffi.itemKinds

/** One consistent icon per item kind. */
fun kindIcon(kind: String): ImageVector = when (kind) {
    "login" -> Icons.Rounded.Language
    "password" -> Icons.Rounded.Password
    "note" -> Icons.Rounded.StickyNote2
    "card" -> Icons.Rounded.CreditCard
    "identity" -> Icons.Rounded.Person
    "document" -> Icons.Rounded.Description
    "ssh_key" -> Icons.Rounded.Terminal
    "api_credential" -> Icons.Rounded.Api
    "bank" -> Icons.Rounded.AccountBalance
    "database" -> Icons.Rounded.Storage
    "server" -> Icons.Rounded.Dns
    "wifi" -> Icons.Rounded.Wifi
    "passport" -> Icons.Rounded.FlightTakeoff
    "driver_license" -> Icons.Rounded.DirectionsCar
    "membership" -> Icons.Rounded.CardMembership
    "crypto_wallet" -> Icons.Rounded.CurrencyBitcoin
    "software_license" -> Icons.Rounded.VerifiedUser
    else -> Icons.Rounded.Key
}

fun kindName(kind: String) = itemKinds().firstOrNull { it.id == kind }?.name ?: kind.replace('_', ' ').replaceFirstChar { it.uppercase() }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemsScreen() {
    val model = LocalContext.current.model
    var picking by remember { mutableStateOf(false) }
    Scaffold(
        containerColor = P.bg,
        topBar = {
            Column(Modifier.background(P.bg).statusBarsPadding()) {
                Row(Modifier.fillMaxWidth().padding(start = 8.dp, end = 8.dp, top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    VaultMenu()
                    Spacer(Modifier.weight(1f))
                    if (model.syncing) androidx.compose.material3.CircularProgressIndicator(Modifier.size(18.dp).padding(end = 4.dp), strokeWidth = 2.dp)
                }
                SearchField()
            }
        },
        floatingActionButton = {
            if (model.accounts.isNotEmpty()) FloatingActionButton(onClick = { picking = true }, containerColor = P.accent, contentColor = P.accentFg) {
                Icon(Icons.Rounded.Add, "New item")
            }
        },
    ) { pad ->
        PullToRefreshBox(isRefreshing = model.syncing, onRefresh = { model.syncAll() }, modifier = Modifier.padding(pad).fillMaxSize()) {
            if (model.items.isEmpty()) {
                Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center) {
                    if (model.query.isEmpty() && model.filter == Filter.All) {
                        EmptyState(Icons.Rounded.Key, "Add your first login, or import from 1Password or Bitwarden.") {
                            Column(Modifier.widthIn(max = 280.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                PrimaryButton("Add a login", { model.newItem("login") })
                                SecondaryButton("Import", { model.push(Route.Import) })
                            }
                        }
                    } else {
                        EmptyState(Icons.Rounded.Search, if (model.query.isEmpty()) "Nothing here yet." else "Nothing matches “${model.query}”.")
                    }
                }
            } else {
                val favorites = if (model.filter == Filter.Favorites || model.vault.sortRecent) emptyList() else model.items.filter { it.favorite }
                val rest = model.items.filter { it !in favorites }
                LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 96.dp)) {
                    if (favorites.isNotEmpty()) {
                        item { SectionTitle("Favorites") }
                        items(favorites, key = { "f/" + it.ref.key }) { ItemRow(it) }
                        item { SectionTitle("All items") }
                    }
                    items(rest, key = { it.ref.key }) { ItemRow(it) }
                }
            }
        }
    }
    if (picking) KindPicker(onDismiss = { picking = false }) { kind -> picking = false; model.newItem(kind) }
}

/** The vault picker: All items, Favorites, each account's vaults, Archive. */
@Composable
private fun VaultMenu() {
    val model = LocalContext.current.model
    var open by remember { mutableStateOf(false) }
    val title = when (val f = model.filter) {
        Filter.All -> "All items"
        Filter.Favorites -> "Favorites"
        Filter.Archive -> "Archive"
        is Filter.Vault -> model.vault(f.account, f.id)?.name ?: "Vault"
    }
    Box {
        Row(
            Modifier.clip(RoundedCornerShape(8.dp)).clickable { open = true }.padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = P.fg)
            Icon(Icons.Rounded.ExpandMore, "Choose vault", tint = P.muted)
        }
        DropdownMenu(open, { open = false }) {
            fun pick(f: Filter) { model.filter = f; model.reload(); open = false }
            DropdownMenuItem({ Text("All items") }, { pick(Filter.All) }, leadingIcon = { Icon(Icons.Rounded.Key, null) })
            DropdownMenuItem({ Text("Favorites") }, { pick(Filter.Favorites) }, leadingIcon = { Icon(Icons.Rounded.Star, null) })
            model.accounts.forEach { a ->
                HorizontalDivider()
                if (model.accounts.size > 1) Text(accountLabel(a.server, a.username), color = P.muted, style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp))
                model.vaults.filter { it.accountId == a.id }.forEach { v ->
                    DropdownMenuItem(
                        { Text(v.name.ifEmpty { "Untitled vault" }) }, { pick(Filter.Vault(v.accountId, v.id)) },
                        leadingIcon = { Icon(if (v.members.size > 1) Icons.Rounded.Group else Icons.Rounded.Lock, null) },
                        trailingIcon = { Text("${v.itemCount}", color = P.muted) },
                    )
                }
            }
            HorizontalDivider()
            DropdownMenuItem({ Text("Archive") }, { pick(Filter.Archive) }, leadingIcon = { Icon(Icons.Rounded.Archive, null) })
        }
    }
}

@Composable
private fun SearchField() {
    val model = LocalContext.current.model
    TextField(
        value = model.query, onValueChange = { model.query = it; model.reload() },
        placeholder = { Text("Search") }, singleLine = true,
        leadingIcon = { Icon(Icons.Rounded.Search, null, tint = P.muted) },
        trailingIcon = { if (model.query.isNotEmpty()) IconButton(onClick = { model.query = ""; model.reload() }) { Icon(Icons.Rounded.Close, "Clear search", tint = P.muted) } },
        shape = RoundedCornerShape(10.dp),
        colors = TextFieldDefaults.colors(
            focusedContainerColor = P.surface, unfocusedContainerColor = P.surface,
            focusedIndicatorColor = Color.Transparent, unfocusedIndicatorColor = Color.Transparent,
        ),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

/**
 * A row: monogram, title, secondary line. Tap opens it; long-press shows the quick actions; swiping right copies
 * the password, swiping left adds to or removes from Favorites.
 */
@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class)
@Composable
fun ItemRow(s: ItemSummary, onClick: (() -> Unit)? = null) {
    val model = LocalContext.current.model
    var menu by remember { mutableStateOf(false) }
    val multi = model.accounts.size > 1 || model.vaults.size > 1
    val secondary = if (model.filter is Filter.Vault || !multi) s.subtitle else listOf(s.subtitle, s.vaultName).filter { it.isNotEmpty() }.joinToString(" · ")
    val current by rememberUpdatedState(s)
    val state = rememberSwipeToDismissBoxState(confirmValueChange = {
        val s = current
        when (it) {
            SwipeToDismissBoxValue.StartToEnd -> if (s.hasPassword) model.copyField(s.ref, "password")
            SwipeToDismissBoxValue.EndToStart -> model.setFlags(s.ref, !s.favorite, s.archived)
            else -> {}
        }
        false
    })
    val actions = buildList {
        if (s.hasUsername) add(CustomAccessibilityAction("Copy username") { model.copyField(s.ref, "username"); true })
        if (s.hasPassword) add(CustomAccessibilityAction("Copy password") { model.copyField(s.ref, "password"); true })
        if (s.hasTotp) add(CustomAccessibilityAction("Copy one-time code") { model.copyField(s.ref, "totp"); true })
        add(CustomAccessibilityAction(if (s.favorite) "Remove from Favorites" else "Add to Favorites") { model.setFlags(s.ref, !s.favorite, s.archived); true })
    }
    SwipeToDismissBox(
        state = state,
        enableDismissFromStartToEnd = s.hasPassword && onClick == null,
        enableDismissFromEndToStart = onClick == null,
        backgroundContent = {
            val toEnd = state.dismissDirection == SwipeToDismissBoxValue.StartToEnd
            Row(
                Modifier.fillMaxSize().background(if (toEnd) P.accent else P.warn).padding(horizontal = 24.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = if (toEnd) Arrangement.Start else Arrangement.End,
            ) {
                Text(if (toEnd) "Copy password" else if (s.favorite) "Unfavorite" else "Favorite", color = P.accentFg, fontWeight = FontWeight.SemiBold)
            }
        },
    ) {
        Box {
            Row(
                Modifier.fillMaxWidth().background(P.bg)
                    .combinedClickable(onClick = { onClick?.invoke() ?: model.push(Route.Item(s.ref)) }, onLongClick = { if (onClick == null) menu = true })
                    .semantics { customActions = actions }
                    .heightIn(min = 60.dp).padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Monogram(s.title)
                Column(Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(s.title.ifEmpty { "Untitled" }, color = P.fg, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                        if (s.favorite) { Spacer(Modifier.width(4.dp)); Icon(Icons.Rounded.Star, "Favorite", tint = Color(0xFFE0A800), modifier = Modifier.size(14.dp)) }
                    }
                    if (secondary.isNotEmpty()) Text(secondary, color = P.muted, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            DropdownMenu(menu, { menu = false }) {
                if (s.hasUsername) DropdownMenuItem({ Text("Copy username") }, { model.copyField(s.ref, "username"); menu = false })
                if (s.hasPassword) DropdownMenuItem({ Text("Copy password") }, { model.copyField(s.ref, "password"); menu = false })
                if (s.hasTotp) DropdownMenuItem({ Text("Copy one-time code") }, { model.copyField(s.ref, "totp"); menu = false })
                HorizontalDivider()
                DropdownMenuItem({ Text(if (s.favorite) "Remove from Favorites" else "Add to Favorites") }, { model.setFlags(s.ref, !s.favorite, s.archived); menu = false })
                DropdownMenuItem({ Text(if (s.archived) "Unarchive" else "Archive") }, { model.setFlags(s.ref, s.favorite, !s.archived); menu = false })
                DropdownMenuItem({ Text("Edit") }, { model.edit(s.ref); menu = false })
                DropdownMenuItem({ Text("Delete", color = P.danger) }, { model.delete(s.ref, s.title); menu = false })
            }
        }
    }
}

/** New item: a grid of kinds, Login first. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KindPicker(onDismiss: () -> Unit, onPick: (String) -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = P.bg, sheetState = androidx.compose.material3.rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Text("New item", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = P.fg, modifier = Modifier.padding(horizontal = 24.dp))
        LazyVerticalGrid(GridCells.Adaptive(96.dp), Modifier.navigationBarsPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items(itemKinds(), key = { it.id }) { k ->
                Column(
                    Modifier.clip(RoundedCornerShape(12.dp)).background(if (k.id == "login") P.code else P.surface).clickable { onPick(k.id) }.padding(vertical = 14.dp, horizontal = 6.dp),
                    horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Icon(kindIcon(k.id), null, tint = P.accent)
                    Text(k.name, color = P.fg, style = MaterialTheme.typography.labelMedium, textAlign = TextAlign.Center, maxLines = 2)
                }
            }
        }
    }
}
