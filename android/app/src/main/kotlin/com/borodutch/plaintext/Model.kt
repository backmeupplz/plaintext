package com.borodutch.plaintext

import android.content.Context
import android.os.Build
import android.provider.Settings
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.plaintext_ffi.AccountInfo
import uniffi.plaintext_ffi.InboxEntry
import uniffi.plaintext_ffi.ItemData
import uniffi.plaintext_ffi.ItemSummary
import uniffi.plaintext_ffi.PlaintextApp
import uniffi.plaintext_ffi.PlaintextException
import uniffi.plaintext_ffi.Recipe
import uniffi.plaintext_ffi.Role
import uniffi.plaintext_ffi.UnlockData
import uniffi.plaintext_ffi.VaultInfo
import uniffi.plaintext_ffi.WatchItem
import uniffi.plaintext_ffi.breachCount
import uniffi.plaintext_ffi.generatePassword
import uniffi.plaintext_ffi.itemTemplate
import uniffi.plaintext_ffi.totpCode
import java.io.File

/** An error worded for people, raised by the app itself. */
class UserError(message: String) : Exception(message)

/** The sentence to show: written in Rust, so every app says the same. */
fun errorText(e: Throwable): String = when (e) {
    is PlaintextException, is UserError -> e.message ?: ""
    else -> "Something went wrong. Try again."
}

/** Points at one item of one account. */
data class ItemRef(val account: String, val vault: String, val item: String) {
    val key get() = "$account/$vault/$item"
}

val ItemSummary.ref get() = ItemRef(accountId, vaultId, id)
val VaultInfo.key get() = "$accountId/$id"

/** What the home list shows. */
sealed interface Filter {
    data object All : Filter
    data object Favorites : Filter
    data object Archive : Filter
    data class Vault(val account: String, val id: String) : Filter
}

enum class Tab { Items, Watchtower, Inbox, Settings }

/** Screens pushed over the tabs. */
sealed interface Route {
    data class Item(val ref: ItemRef) : Route
    data class Edit(val account: String, val vault: String, val item: String?, val data: ItemData) : Route
    data object Vaults : Route
    data class Vault(val account: String, val id: String) : Route
    data class Verify(val account: String, val username: String) : Route
    data object Agents : Route
    data object Import : Route
    data class AddDevice(val account: String) : Route
    data class Account(val account: String) : Route
    data object Security : Route
    data object AddAccount : Route
    data class People(val account: String) : Route
}

data class Toast(val text: String, val undo: (() -> Unit)? = null, val id: Long = System.nanoTime())

/**
 * The app's state, one per process (Activity recreation keeps it). Rust holds the keys and the vaults; this
 * keeps the lists Compose draws, re-read after every change.
 */
class Model(val context: Context) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    val vault = Vault(context)
    val core = PlaintextApp(File(context.noBackupFilesDir, "plaintext").apply { mkdirs() }.path, deviceName(context))

    var known by mutableStateOf(vault.known)
        private set
    var accounts by mutableStateOf(listOf<AccountInfo>())
    var locked by mutableStateOf(true)
    var unlocking by mutableStateOf(false)

    var vaults by mutableStateOf(listOf<VaultInfo>())
    var items by mutableStateOf(listOf<ItemSummary>())
    var watch by mutableStateOf(listOf<WatchItem>())
    var inbox by mutableStateOf(mapOf<String, List<InboxEntry>>())
    /** Passwords found in breaches, by item key, once the check ran. */
    var breached by mutableStateOf(mapOf<String, ULong>())

    var filter: Filter by mutableStateOf(Filter.All)
    var query by mutableStateOf("")
    var tab by mutableStateOf(Tab.Items)
    val stack = mutableStateListOf<Route>()

    var toast by mutableStateOf<Toast?>(null)
    var banner by mutableStateOf<String?>(null)
    var syncing by mutableStateOf(false)
    /** Hidden from lists while their undo toast is up. */
    private val deleting = mutableSetOf<String>()

    /** What unlocks each open account, kept while unlocked so turning biometrics on needs no password. */
    private val unlocks = mutableMapOf<String, UnlockData>()
    private var lastTouch = System.currentTimeMillis()
    private var idleJob: Job? = null

    /** Run a blocking Rust call off the main thread. */
    suspend fun <T> call(work: (PlaintextApp) -> T): T = withContext(Dispatchers.IO) { work(core) }

    /** Run a Rust call and show its error, if any. */
    fun act(work: suspend () -> Unit) {
        scope.launch { try { work() } catch (e: Exception) { show(e) } }
    }

    fun show(e: Throwable) {
        if (e is PlaintextException.SignedOut) reload()
        banner = errorText(e)
    }

    fun flash(text: String, undo: (() -> Unit)? = null) {
        toast = Toast(text, undo)
    }

    fun copy(text: String, what: String, sensitive: Boolean = true) {
        Clipboard.copy(context, text, sensitive, vault.clipboardSeconds, scope)
        flash("$what copied")
    }

    fun push(r: Route) = stack.add(r)
    fun pop() { if (stack.isNotEmpty()) stack.removeAt(stack.lastIndex) }

    // ----- Accounts -----

    fun known(id: String) = known.firstOrNull { it.id == id }
    fun account(id: String) = accounts.firstOrNull { it.id == id }
    val lockedAccounts get() = known.filter { k -> accounts.none { it.id == k.id } }

    private fun storeKnown(v: List<KnownAccount>) {
        known = v
        vault.known = v
    }

    /** After signup or sign-in: remember the account and what unlocks it. */
    fun added(info: AccountInfo, unlock: UnlockData, secretKey: String) {
        storeKnown(known.filter { it.id != info.id } + KnownAccount(info.id, info.server, info.username))
        vault.saveSecretKey(info.id, secretKey)
        saveSession(info.id, unlock)
        unlocked()
    }

    private fun saveSession(id: String, u: UnlockData) {
        unlocks[id] = u
        if (vault.biometrics && Vault.biometricsAvailable(context)) vault.saveSession(id, u) else vault.forgetSession(id)
    }

    /** Re-store every open account's session after the biometrics setting changes. */
    fun biometricsChanged(on: Boolean) {
        vault.biometrics = on
        if (!on) vault.forgetAllSessions() else unlocks.forEach { (id, u) -> vault.saveSession(id, u) }
    }

    /** After a successful biometric prompt: open every account with a stored session. */
    fun unlockWithStoredSessions() {
        if (!locked || unlocking) return
        unlocking = true
        scope.launch {
            val sessions = try {
                vault.sessions()
            } catch (e: Exception) {
                // A new fingerprint or face was enrolled (or the key is gone): the password is needed once.
                vault.forgetAllSessions()
                banner = "Your fingerprints or face changed, so enter your password once to turn biometric unlock back on."
                unlocking = false
                return@launch
            }
            val errors = mutableListOf<String>()
            for (k in known) {
                val u = sessions[k.id] ?: continue
                if (account(k.id) != null) continue
                try {
                    call { it.resume(k.server, u) }
                    unlocks[k.id] = u
                } catch (e: PlaintextException.SignedOut) {
                    vault.forgetSession(k.id)
                    errors += "${k.name} was signed out. Enter its password to sign in again."
                } catch (e: Exception) {
                    errors += errorText(e)
                }
            }
            unlocking = false
            reload()
            if (accounts.isNotEmpty()) unlocked()
            banner = errors.firstOrNull()
        }
    }

    /** Unlock one account with its password; the Secret Key is kept on this device. */
    suspend fun unlock(k: KnownAccount, password: String) {
        val sk = vault.secretKey(k.id) ?: throw UserError("This device lost its copy of the Secret Key. Sign in again with your Emergency Kit.")
        val r = call { it.login(k.server, sk, password) }
        saveSession(k.id, r.unlock)
        unlocked()
    }

    private fun unlocked() {
        locked = false
        touch()
        reload()
        idleJob?.cancel()
        idleJob = scope.launch {
            while (isActive) {
                delay(15_000)
                val minutes = vault.autoLockMinutes
                if (minutes > 0 && System.currentTimeMillis() - lastTouch > minutes * 60_000L) lock()
            }
        }
        syncAll()
    }

    /** Any touch or key press counts as activity for auto-lock. */
    fun touch() { lastTouch = System.currentTimeMillis() }

    /** Set while a file picker, share sheet or print dialog is up, so "lock immediately" doesn't fire for it. */
    var external = false

    /** The app went to the background: lock now if set to, or if it's been idle long enough on return. */
    fun backgrounded() { if (vault.autoLockMinutes == 0 && !external) lock() }
    fun foregrounded() {
        external = false
        val minutes = vault.autoLockMinutes
        if (!locked && minutes > 0 && System.currentTimeMillis() - lastTouch > minutes * 60_000L) lock()
    }

    fun lock() {
        if (locked && accounts.isEmpty()) return
        idleJob?.cancel()
        core.lock()
        unlocks.values.forEach { it.accountKey.fill(0) }
        unlocks.clear()
        accounts = emptyList(); items = emptyList(); vaults = emptyList(); watch = emptyList()
        inbox = emptyMap(); breached = emptyMap()
        stack.clear()
        tab = Tab.Items
        filter = Filter.All
        query = ""
        Clipboard.clear(context)
        wipeCache()
        locked = true
    }

    /** Opened attachments are decrypted into the cache; they go on lock and sign-out. */
    fun wipeCache() {
        File(context.cacheDir, "open").deleteRecursively()
    }

    fun signOut(id: String) = scope.launch {
        withContext(Dispatchers.IO) { core.signOut(id) }
        vault.forget(id)
        unlocks.remove(id)?.accountKey?.fill(0)
        storeKnown(known.filter { it.id != id })
        inbox = inbox - id
        wipeCache()
        reload()
        if (known.isEmpty() || accounts.isEmpty()) lock()
    }

    // ----- Data -----

    /** Re-read lists from Rust's in-memory copies: cheap, no network. */
    fun reload() {
        accounts = core.accounts()
        vaults = core.vaults()
        watch = core.watchtower()
        val all = { archived: Boolean -> core.items(null, null, query, archived) }
        var list = when (val f = filter) {
            is Filter.Vault -> core.items(f.account, f.id, query, false)
            Filter.Archive -> all(true)
            Filter.Favorites -> all(false).filter { it.favorite }
            Filter.All -> all(false)
        }
        if (vault.sortRecent) list = list.sortedByDescending { it.updated }
        items = list.filter { it.ref.key !in deleting }
    }

    fun syncAll() {
        if (locked || syncing) return
        syncing = true
        scope.launch {
            val ids = accounts.map { it.id }
            val results = ids.map { id ->
                async(Dispatchers.IO) {
                    try {
                        core.sync(id)
                        Triple(id, null, runCatching { core.inbox(id) }.getOrNull())
                    } catch (e: Exception) {
                        // The server ended this session: drop it here too (the password signs in again).
                        if (e is PlaintextException.SignedOut) core.signOut(id)
                        Triple(id, e, null)
                    }
                }
            }.awaitAll()
            var first: Exception? = null
            val box = inbox.toMutableMap()
            for ((id, err, entries) in results) {
                if (entries != null) box[id] = entries
                when (err) {
                    null, is PlaintextException.Network -> {}
                    is PlaintextException.SignedOut -> {
                        vault.forgetSession(id)
                        unlocks.remove(id)?.accountKey?.fill(0)
                        first = first ?: err
                    }
                    else -> first = first ?: err
                }
            }
            if (!locked) inbox = box
            syncing = false
            reload()
            first?.let { show(it) }
        }
    }

    val inboxCount get() = inbox.values.sumOf { l -> l.count { it.id.isNotEmpty() } }

    fun vault(account: String, id: String) = vaults.firstOrNull { it.accountId == account && it.id == id }

    /** Where a new item goes: the selected vault if writable, else the default vault of its (or the first) account. */
    fun newItemTarget(): Pair<String, String>? {
        (filter as? Filter.Vault)?.let { f ->
            val v = vault(f.account, f.id)
            if (v?.role != null && v.role != Role.READER) return f.account to f.id
        }
        val acct = (filter as? Filter.Vault)?.account ?: accounts.firstOrNull()?.id ?: return null
        val d = vaults.firstOrNull { it.accountId == acct && it.isDefault } ?: return null
        return acct to d.id
    }

    fun newItem(kind: String) {
        val (a, v) = newItemTarget() ?: run { banner = "There's no vault you can add items to yet."; return }
        val data = itemTemplate(kind)
        if (kind == "login" || kind == "password") data.password = generatePassword(Recipe.Random(20u, true, true))
        push(Route.Edit(a, v, null, data))
    }

    fun edit(ref: ItemRef) {
        val data = runCatching { core.item(ref.account, ref.vault, ref.item) }.getOrNull() ?: return
        push(Route.Edit(ref.account, ref.vault, ref.item, data))
    }

    fun summary(ref: ItemRef): ItemSummary? =
        (core.items(ref.account, ref.vault, "", false) + core.items(ref.account, ref.vault, "", true)).firstOrNull { it.id == ref.item }

    fun setFlags(ref: ItemRef, favorite: Boolean, archived: Boolean) = act {
        call { it.setFlags(ref.account, ref.vault, ref.item, favorite, archived) }
        reload()
    }

    /** Deleting waits a few seconds behind an undo toast instead of asking first. */
    fun delete(ref: ItemRef, title: String) {
        deleting += ref.key
        stack.removeAll { it is Route.Item && it.ref == ref }
        reload()
        var undone = false
        flash("Deleted $title") {
            undone = true
            deleting -= ref.key
            reload()
        }
        scope.launch {
            delay(5_000)
            if (undone) return@launch
            try { call { it.deleteItem(ref.account, ref.vault, ref.item) } } catch (e: Exception) { show(e) }
            deleting -= ref.key
            reload()
        }
    }

    /** Copy one field of an item from a list row. */
    fun copyField(ref: ItemRef, which: String) {
        val d = runCatching { core.item(ref.account, ref.vault, ref.item) }.getOrNull() ?: return
        when (which) {
            "username" -> if (d.username.isNotEmpty()) copy(d.username, "Username", sensitive = false)
            "totp" -> totpCode(d.totp)?.let { copy(it.code, "One-time code") }
            else -> if (d.password.isNotEmpty()) copy(d.password, "Password")
        }
    }

    /** Only the first five characters of each password's SHA-1 leave the device. */
    suspend fun runBreachCheck() {
        val found = mutableMapOf<String, ULong>()
        val seen = mutableMapOf<String, ULong>()
        for (s in core.items(null, null, "", false).filter { it.hasPassword }) {
            val pw = runCatching { core.item(s.accountId, s.vaultId, s.id).password }.getOrNull() ?: continue
            val n = seen[pw] ?: (runCatching { withContext(Dispatchers.IO) { breachCount(pw) } }.getOrNull() ?: continue).also { seen[pw] = it }
            if (n > 0u) found[s.ref.key] = n
        }
        breached = found
    }

    companion object {
        fun deviceName(c: Context): String =
            Settings.Global.getString(c.contentResolver, Settings.Global.DEVICE_NAME)?.takeIf { it.isNotBlank() } ?: Build.MODEL
    }
}
