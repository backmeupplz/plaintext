package com.borodutch.plaintext

import android.content.Context
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
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
import java.security.UnrecoverableKeyException

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

    // Left over if the process died while unlocked.
    init { File(context.cacheDir, "open").deleteRecursively() }

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
    /** Bumped on every reload, so screens reading Rust directly (item detail) re-read too. */
    var version by mutableStateOf(0)
        private set
    /** Hidden from lists while their undo toast is up. */
    private val deleting = mutableSetOf<String>()

    /** First run, between signup (or sign-in) and the end of onboarding: [known] is no longer empty. */
    var onboarding by mutableStateOf(false)
    /** An account added while unlocked whose onboarding hasn't finished: what [abandonSetup] stores if it never does. */
    private var pending: Pair<String, UnlockData>? = null
    /** Bumped by every lock that does something; an unlock or signup that sees it change gives up. */
    private var epoch = 0
    /** Unlocks in flight: a lock must still go through while one runs. */
    private var opening = 0
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

    /** Right after signup or sign-in, before the Emergency Kit is on screen: keep the account and its Secret Key (the app may be killed there). */
    fun remember(info: AccountInfo, secretKey: String, unlock: UnlockData) {
        val k = KnownAccount(info.id, info.server, info.username)
        if (known.isEmpty()) onboarding = true
        pending = info.id to unlock
        // Same name on the same server: an old account of a reset server is gone.
        known.filter { it.id != k.id && it.name == k.name }.forEach { vault.forget(it.id) }
        storeKnown(known.filter { it.id != k.id && it.name != k.name } + k)
        vault.saveSecretKey(info.id, secretKey)
    }

    /**
     * Signup or sign-in that finishes even if the screen that started it goes away, so the Secret Key of an account
     * that now exists is never lost. A lock meanwhile leaves the account stored but closed.
     */
    suspend fun <T> addAccount(work: (PlaintextApp) -> T, parts: (T) -> Triple<AccountInfo, String, UnlockData>): T {
        val e = epoch
        return scope.async {
            val r = call(work)
            val (info, sk, u) = parts(r)
            remember(info, sk, u)
            if (epoch != e) {
                abandonSetup()
                if (locked) core.lock(!sessionsStored) else reload()
            }
            r
        }.await()
    }

    /** Onboarding is done: store what unlocks the account and open it. */
    fun added(info: AccountInfo, unlock: UnlockData, secretKey: String) {
        remember(info, secretKey, unlock)
        pending = null
        onboarding = false
        saveSession(info.id, unlock)
        unlocked()
    }

    /** An added account's onboarding ended early (a lock, say, on the kit step): keep its session as onboarding would have. */
    fun abandonSetup() {
        val (id, u) = pending ?: return
        pending = null
        saveSession(id, u)
        known(id)?.let { banner = "${it.name} was added. Save its Emergency Kit from Settings → ${it.username}." }
    }

    /** Nothing on this device can resume a session without the password. */
    private val sessionsStored get() = vault.biometrics && Vault.biometricsAvailable(context)

    private fun saveSession(id: String, u: UnlockData) {
        if (sessionsStored) vault.saveSession(id, u) else vault.forgetSession(id)
        u.accountKey.fill(0)
    }

    /** Re-store every open account's session after the biometrics setting changes. */
    fun biometricsChanged(on: Boolean) {
        vault.biometrics = on
        if (!on) return vault.forgetAllSessions()
        val ids = accounts.map { it.id }
        scope.launch {
            for (id in ids) runCatching { call { it.unlockData(id) } }.onSuccess { saveSession(id, it) }
        }
    }

    /** After a successful biometric prompt: open every account with a stored session. */
    fun unlockWithStoredSessions() {
        if (!locked || unlocking) return
        unlocking = true
        val e = epoch
        opening++ // from the start: a lock while the Keystore decrypts must still go through
        scope.launch {
            try {
                val sessions = try {
                    withContext(Dispatchers.IO) { vault.sessions() }
                } catch (x: Exception) {
                    if (x is KeyPermanentlyInvalidatedException || x is UnrecoverableKeyException) {
                        // A new fingerprint or face was enrolled (or the key is gone): the password is needed once.
                        vault.forgetAllSessions()
                        banner = "Your fingerprints or face changed, so enter your password once to turn biometric unlock back on."
                    } else {
                        banner = "Couldn't open your vaults with your fingerprint. Try again, or use your password."
                    }
                    unlocking = false
                    return@launch
                }
                val errors = mutableListOf<String>()
                for (k in known) {
                    if (epoch != e) break
                    val u = sessions[k.id] ?: continue
                    if (account(k.id) != null) continue
                    try {
                        call { it.resume(k.server, u) }
                    } catch (x: PlaintextException.SignedOut) {
                        vault.forgetSession(k.id)
                        errors += "${k.name} was signed out. Enter its password to sign in again."
                    } catch (x: Exception) {
                        errors += errorText(x)
                    }
                }
                sessions.values.forEach { it.accountKey.fill(0) }
                unlocking = false
                // Locked again while opening (the screen went off), and still locked: stay that way.
                if (epoch != e && locked) return@launch core.lock(!sessionsStored)
                reload()
                if (accounts.isNotEmpty()) unlocked()
                banner = errors.firstOrNull()
            } finally {
                opening--
            }
        }
    }

    /** Unlock one account with its password; the Secret Key is kept on this device. */
    suspend fun unlock(k: KnownAccount, password: String) {
        val sk = vault.secretKey(k.id) ?: throw UserError("This device lost its copy of the Secret Key. Sign in again with your Emergency Kit.")
        val e = epoch
        opening++
        val r = try { call { it.login(k.server, sk, password) } } finally { opening-- }
        saveSession(k.id, r.unlock)
        // Locked again while signing in, and still locked: stay that way.
        if (epoch != e && locked) return core.lock(!sessionsStored)
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
        if (locked && accounts.isEmpty() && opening == 0) return
        epoch++
        idleJob?.cancel()
        abandonSetup()
        // Without a stored session the next unlock signs in again, so end these.
        core.lock(!sessionsStored)
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

    /** Sign out of one account. A locked one's server session ends too when [withStored] (right after a biometric prompt). */
    fun signOut(id: String, withStored: Boolean = false) = scope.launch {
        val server = known(id)?.server ?: return@launch
        withContext(Dispatchers.IO) {
            val stored = if (withStored) runCatching { vault.session(id) }.getOrNull() else null
            core.signOut(id, server, stored)
            stored?.accountKey?.fill(0)
        }
        vault.forget(id)
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
        version++
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
                        // Keep this device's copies: they hold the rollback guard and pins.
                        if (e is PlaintextException.SignedOut) core.forget(id)
                        Triple(id, e, null)
                    }
                }
            }.awaitAll()
            var first: Exception? = null
            val box = inbox.toMutableMap()
            for ((id, err, entries) in results) {
                if (entries != null) box[id] = entries
                when (err) {
                    null, is PlaintextException.Network, is PlaintextException.Locked -> {}
                    is PlaintextException.SignedOut -> {
                        vault.forgetSession(id)
                        first = first ?: err
                    }
                    else -> first = first ?: err
                }
            }
            if (!locked) inbox = box
            syncing = false
            reload()
            // The server signed this device out of its only open account.
            if (accounts.isEmpty() && !locked) lock()
            // What the sync couldn't do; the client's text can end with a CLI hint, and the app has its own Verify screen.
            val problem = accounts.flatMap { it.problems }.firstOrNull()?.substringBefore(" (plaintext ")?.replaceFirstChar { it.uppercase() }
            if (first != null) show(first!!) else if (problem != null) banner = problem
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
            // Locked meanwhile: delete once it's open again.
            snapshotFlow { locked }.first { !it }
            try {
                call { it.deleteItem(ref.account, ref.vault, ref.item) }
            } catch (_: PlaintextException.Locked) {
            } catch (e: Exception) {
                show(e)
            }
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
