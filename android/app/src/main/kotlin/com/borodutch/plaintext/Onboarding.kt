package com.borodutch.plaintext

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AutoAwesome
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Cloud
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Print
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.RadioButtonUnchecked
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import uniffi.plaintext_ffi.LoginResult
import uniffi.plaintext_ffi.Recipe
import uniffi.plaintext_ffi.ServerInfo
import uniffi.plaintext_ffi.PlaintextException
import uniffi.plaintext_ffi.SignupResult
import uniffi.plaintext_ffi.cloudServer
import uniffi.plaintext_ffi.generatePassword
import uniffi.plaintext_ffi.normalizeSecretKey
import uniffi.plaintext_ffi.parseDeviceCode
import uniffi.plaintext_ffi.passwordStrength
import uniffi.plaintext_ffi.serverAddress
import uniffi.plaintext_ffi.serverInfo
import uniffi.plaintext_ffi.validUsername

private enum class Step { Server, Create, Kit, Biometrics, Username, SecretKey, Password, Scan }

/** The onboarding state. Lives only as long as the flow (never saved): it holds the password while typed. */
private class Flow {
    val path = mutableStateListOf<Step>()
    var create = true
    var useCloud by mutableStateOf(false)
    var custom by mutableStateOf("")
    var server by mutableStateOf("")
    var info by mutableStateOf<ServerInfo?>(null)
    var username by mutableStateOf("")
    var password by mutableStateOf("")
    var invite by mutableStateOf("")
    var secretKey by mutableStateOf("")
    var signup: SignupResult? = null
    var login: LoginResult? = null
    fun go(s: Step) = path.add(s)
    fun back() { if (path.isNotEmpty()) path.removeAt(path.lastIndex) }
}

/** Rust's network message talks about items already on this device, and there are none yet. */
private fun setupError(e: Throwable, typedAddress: Boolean = false) = when {
    e !is PlaintextException.Network -> errorText(e)
    typedAddress -> "Couldn't reach that server. Check the address, and add http:// if it doesn't use https."
    else -> "Couldn't reach the server. Check your connection and try again."
}

/**
 * Welcome → Server → Create account → Emergency Kit → biometrics, or Welcome → Server → username → Secret Key
 * (scan or type) → password. Also *Add account* from Settings and the lock screen.
 */
@Composable
fun Onboarding(adding: Boolean = false, onClose: (() -> Unit)? = null) {
    val flow = remember { Flow() }
    val step = flow.path.lastOrNull()
    val model = LocalContext.current.model
    // Gone before finishing (say, the app locked on the kit step): the added account keeps its session.
    DisposableEffect(Unit) { onDispose { model.abandonSetup() } }
    // The kit and biometrics steps can't be backed out of: the account already exists.
    BackHandler(enabled = step != null || onClose != null) {
        when {
            step == Step.Kit || step == Step.Biometrics -> {}
            step != null -> flow.back()
            else -> onClose?.invoke()
        }
    }
    val done = { onClose?.invoke(); Unit }
    when (step) {
        null -> Welcome(adding, onClose, flow)
        Step.Server -> ServerStep(flow)
        Step.Create -> CreateStep(flow)
        Step.Kit -> KitStep(flow)
        Step.Biometrics -> BiometricsStep(flow, done)
        Step.Username -> UsernameStep(flow)
        Step.SecretKey -> SecretKeyStep(flow)
        Step.Password -> PasswordStep(flow)
        Step.Scan -> Screen("Scan from another device", onBack = { flow.back() }, close = true) { m ->
            Column(m) {
                Scanner("On your other device, open Settings → Add a device.") { code ->
                    val d = parseDeviceCode(code) ?: return@Scanner "That isn't a Plaintext sign-in code."
                    val address = runCatching { serverAddress(d.server) }.getOrElse { return@Scanner errorText(it) }
                    flow.server = address.url
                    flow.username = d.username
                    flow.secretKey = d.secretKey
                    flow.back()
                    flow.go(Step.Password)
                    null
                }
            }
        }
    }
}

@Composable
private fun Welcome(adding: Boolean, onClose: (() -> Unit)?, flow: Flow) {
    Column(
        Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        if (onClose != null) Row(Modifier.fillMaxWidth()) { TextButton(onClick = onClose) { Text("Cancel") } }
        Spacer(Modifier.weight(1f))
        Icon(Icons.Rounded.Shield, null, tint = P.accent, modifier = Modifier.size(48.dp))
        Spacer(Modifier.height(16.dp))
        Wordmark(40.sp)
        Spacer(Modifier.height(16.dp))
        Text(
            if (adding) "Add an account on any server: your family's, your work's, or Plaintext Cloud."
            else "Your passwords, encrypted on your devices. Your server only ever sees ciphertext.",
            style = MaterialTheme.typography.titleMedium, color = P.muted, textAlign = TextAlign.Center,
            modifier = Modifier.widthIn(max = 420.dp),
        )
        Spacer(Modifier.weight(1f))
        Column(Modifier.widthIn(max = 420.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            PrimaryButton("Create account", { flow.create = true; flow.go(Step.Server) })
            SecondaryButton("Sign in", { flow.create = false; flow.go(Step.Server) })
        }
    }
}

@Composable
private fun ServerStep(flow: Flow) {
    val model = LocalContext.current.model
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val cloud = cloudServer()
    val recents = model.vault.recentServers.filter { it != cloud }
    val insecure = !flow.useCloud && runCatching { serverAddress(flow.custom).insecure }.getOrDefault(false)

    fun next() {
        error = null
        val address = runCatching { serverAddress(if (flow.useCloud) cloud else flow.custom) }.getOrElse { error = errorText(it); return }
        busy = true
        scope.launch {
            try {
                val info = model.call { serverInfo(address.url) }
                flow.server = address.url
                flow.info = info
                model.vault.recentServers = listOf(address.url) + model.vault.recentServers.filter { it != address.url }
                if (flow.path.lastOrNull() == Step.Server) flow.go(if (flow.create) Step.Create else Step.Username)
            } catch (e: Exception) {
                error = setupError(e, typedAddress = !flow.useCloud)
            } finally {
                busy = false
            }
        }
    }

    StepPage(
        "Where are your vaults?", "Pick the server that keeps your encrypted vaults. You can add accounts on other servers later.",
        onBack = { flow.back() },
        actions = { PrimaryButton("Continue", ::next, enabled = flow.useCloud || flow.custom.isNotBlank(), busy = busy) },
    ) {
        Choice(flow.useCloud, "Plaintext Cloud", "We run the server for you, so there's nothing to set up.", Icons.Rounded.Cloud) { flow.useCloud = true }
        Choice(!flow.useCloud, "My own server", "The Plaintext server you or your family run.", Icons.Rounded.Dns) { flow.useCloud = false }
        if (!flow.useCloud) {
            Field(
                "Server address", flow.custom, { flow.custom = it }, kind = Input.Url, placeholder = "vault.example.com",
                note = "A domain, an IP address or a Tailscale name, with a port if it needs one.", onDone = ::next,
            )
            if (insecure) Note("Without https, anyone on your network can see which server you use.")
            if (recents.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Recent", color = P.muted, style = MaterialTheme.typography.labelLarge)
                    recents.forEach { r ->
                        Row(
                            Modifier.fillMaxWidth().clickable { flow.custom = r }.padding(vertical = 10.dp),
                            horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(Icons.Rounded.History, null, tint = P.accent, modifier = Modifier.size(18.dp))
                            Text(r, color = P.accent, fontFamily = Mono, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        }
        ErrorNote(error)
    }
}

@Composable
private fun Choice(selected: Boolean, title: String, detail: String, icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit) {
    Card(Modifier.semantics { this.selected = selected }.clickable(role = Role.RadioButton, onClick = onClick), selected = selected) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            Icon(icon, null, tint = P.accent, modifier = Modifier.size(28.dp))
            Column(Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold, color = P.fg)
                Text(detail, color = P.muted, style = MaterialTheme.typography.bodyMedium)
            }
            Icon(if (selected) Icons.Rounded.CheckCircle else Icons.Rounded.RadioButtonUnchecked, null, tint = if (selected) P.accent else P.line)
        }
    }
}

@Composable
private fun CreateStep(flow: Flow) {
    val model = LocalContext.current.model
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // The account may already exist once the server answers: stay until it does.
    BackHandler(enabled = busy) {}
    var reveal by remember { mutableStateOf(false) }
    val needsInvite = flow.info?.open == false
    val setup = flow.info?.setup == true
    val ready = validUsername(flow.username.lowercase()) && passwordStrength(flow.password).level >= 1u &&
        (!needsInvite || setup || flow.invite.isNotBlank()) && (!setup || flow.invite.isNotBlank())

    fun create() {
        error = null
        busy = true
        val (server, username, password, invite) = listOf(flow.server, flow.username.lowercase().trim(), flow.password, flow.invite.trim())
        scope.launch {
            try {
                flow.signup = model.addAccount({ it.signup(server, username, password, invite.ifEmpty { null }) }) { Triple(it.account, it.secretKey, it.unlock) }
                flow.password = ""
                flow.go(Step.Kit)
            } catch (e: Exception) {
                error = setupError(e)
            } finally {
                busy = false
            }
        }
    }

    StepPage(
        "Create your account", "on ${flow.server.substringAfter("://")}", onBack = if (busy) null else ({ flow.back() }),
        actions = { PrimaryButton("Create account", ::create, enabled = ready, busy = busy) },
    ) {
        Field(
            "Username", flow.username, { flow.username = it.lowercase() }, kind = Input.Username, placeholder = "alex",
            note = "Lowercase letters, digits, dots, dashes or underscores. People share vaults with you by this name.",
        )
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Field("Password", flow.password, { flow.password = it }, kind = Input.Password, placeholder = "A long, memorable password", revealed = reveal,
                trailing = {
                    IconButton(onClick = { reveal = !reveal }) {
                        Icon(if (reveal) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility, if (reveal) "Hide password" else "Show password", tint = P.muted)
                    }
                })
            StrengthMeter(flow.password)
            TextButton(onClick = {
                flow.password = generatePassword(Recipe.Memorable(4u, "-", false))
                reveal = true
            }) {
                Icon(Icons.Rounded.AutoAwesome, null, Modifier.size(18.dp))
                Spacer(Modifier.size(6.dp))
                Text("Suggest one")
            }
        }
        if (setup) {
            Field("Setup code", flow.invite, { flow.invite = it }, mono = true, note = "The code the person who runs this server set, so nobody else can claim it first.")
        } else if (needsInvite) {
            Field("Invite code", flow.invite, { flow.invite = it }, mono = true, placeholder = "Paste the invite code", note = "From the person who invited you. It also confirms who they are.")
        }
        ErrorNote(error)
    }
}

@Composable
private fun KitStep(flow: Flow) {
    val context = LocalContext.current
    val r = flow.signup ?: return
    var saved by remember { mutableStateOf(false) }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        if (uri != null) {
            context.model.scope.launch {
                runCatching { EmergencyKit.save(context, uri, r.secretKey, r.account.server, r.account.username) }
                    .onSuccess { saved = true; context.model.flash("Emergency Kit saved") }
                    .onFailure { context.model.banner = "Couldn't save the Emergency Kit there. Try another place." }
            }
        }
    }
    StepPage(
        "Save your Emergency Kit",
        "Your Secret Key and your password together open your account. Nobody can recover them for you, not even whoever runs your server, so keep this kit somewhere safe.",
        onBack = null,
        actions = {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                SecondaryButton("Save as PDF", {
                    context.model.external = true
                    save.launch("Plaintext Emergency Kit - ${r.account.username}.pdf")
                }, Modifier.weight(1f), icon = Icons.Rounded.Save)
                SecondaryButton("Print", { EmergencyKit.print(context, r.secretKey, r.account.server, r.account.username); saved = true }, Modifier.weight(1f), icon = Icons.Rounded.Print)
            }
            PrimaryButton("I've saved it", { flow.go(Step.Biometrics) }, enabled = saved)
            if (!saved) Text("Save or print the kit first.", color = P.muted, style = MaterialTheme.typography.bodySmall, modifier = Modifier.align(Alignment.CenterHorizontally))
        },
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Secret Key", color = P.muted, style = MaterialTheme.typography.labelLarge)
            CodeBlock(
                r.secretKey, style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { contentDescription = "Secret Key " + r.secretKey.toList().joinToString(" ") },
            )
        }
        LabeledValue("Server", r.account.server)
        LabeledValue("Username", r.account.username)
        r.warning?.let { Note(it, icon = Icons.Rounded.Warning) }
    }
}

@Composable
private fun BiometricsStep(flow: Flow, done: () -> Unit) {
    val model = LocalContext.current.model
    val available = Vault.biometricsAvailable(LocalContext.current)
    fun finish(on: Boolean) {
        model.vault.biometrics = on
        flow.signup?.let { model.added(it.account, it.unlock, it.secretKey) }
        flow.login?.let { model.added(it.account, it.unlock, flow.secretKey) }
        flow.secretKey = ""
        done()
    }
    StepPage(
        "Unlock with your fingerprint",
        if (available) "Open Plaintext with your fingerprint or face instead of typing your password each time. Your password is never stored; the keys stay in this phone's secure hardware."
        else if (Vault.canPrompt(LocalContext.current)) "Unlocking with a fingerprint or face needs Android 11 or later, so you'll type your password to unlock."
        else "This phone has no fingerprint or face unlock set up, so you'll type your password to unlock. You can turn biometric unlock on later in Settings.",
        onBack = null,
        actions = {
            if (available) PrimaryButton("Turn on biometric unlock", { finish(true) })
            SecondaryButton(if (available) "Not now" else "Continue", { finish(false) })
        },
    ) {
        Row(Modifier.fillMaxWidth().padding(vertical = 24.dp), horizontalArrangement = Arrangement.Center) {
            Icon(Icons.Rounded.Fingerprint, null, tint = P.accent, modifier = Modifier.size(80.dp))
        }
    }
}

@Composable
private fun UsernameStep(flow: Flow) {
    StepPage(
        "Sign in",
        "On a device where you're already signed in, open Settings → Add a device and scan its code here. Or type your Secret Key from your Emergency Kit.",
        onBack = { flow.back() },
        actions = {
            PrimaryButton("Scan from another device", { flow.go(Step.Scan) }, icon = Icons.Rounded.QrCodeScanner)
            SecondaryButton("Enter Secret Key", { flow.go(Step.SecretKey) }, enabled = validUsername(flow.username.lowercase()))
        },
    ) {
        Field("Username", flow.username, { flow.username = it.lowercase() }, kind = Input.Username, placeholder = "alex")
    }
}

@Composable
private fun SecretKeyStep(flow: Flow) {
    var error by remember { mutableStateOf<String?>(null) }
    fun next() {
        runCatching { normalizeSecretKey(flow.secretKey) }
            .onSuccess { flow.secretKey = it; error = null; flow.go(Step.Password) }
            .onFailure { error = errorText(it) }
    }
    StepPage(
        "Enter your Secret Key", "It's on your Emergency Kit and starts with A1. Dashes and capitals don't matter.", onBack = { flow.back() },
        actions = { PrimaryButton("Continue", ::next, enabled = flow.secretKey.length >= 10) },
    ) {
        Field("Secret Key", flow.secretKey, { flow.secretKey = it }, kind = Input.Secret, placeholder = "A1-XXXXXX-…", singleLine = false, revealed = true, onDone = ::next)
        ErrorNote(error)
    }
}

@Composable
private fun PasswordStep(flow: Flow) {
    val model = LocalContext.current.model
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // The Secret Key of a sign-in this step left waiting for the account's security key.
    var keySk by rememberSaveable { mutableStateOf<String?>(null) }
    // The account may already exist once the server answers: stay until it does.
    BackHandler(enabled = busy) {}
    val insecure = runCatching { serverAddress(flow.server).insecure }.getOrDefault(false)
    fun signIn() {
        if (flow.password.isEmpty()) return
        error = null
        busy = true
        val (server, sk, pw) = Triple(flow.server, flow.secretKey, flow.password)
        scope.launch {
            try {
                flow.login = model.addAccount({ it.login(server, sk, pw) }) { Triple(it.account, sk, it.unlock) }
                flow.password = ""
                flow.go(Step.Biometrics)
            } catch (_: PlaintextException.KeyNeeded) {
                flow.password = ""
                keySk = sk
                model.keyPage = model.core.pendingKeyPage()
            } catch (e: Exception) {
                error = setupError(e)
            } finally {
                busy = false
            }
        }
    }
    StepPage(
        "Enter your password", accountLabel(flow.server, flow.username), onBack = if (busy) null else ({ flow.back() }),
        actions = { PrimaryButton("Sign in", ::signIn, enabled = flow.password.isNotEmpty(), busy = busy) },
    ) {
        val waiting = keySk
        if (waiting != null && model.keyPage != null) KeyStep { code ->
            val sk = waiting
            flow.login = model.addAccount({ it.finishLogin(code) }) { Triple(it.account, sk, it.unlock) }
            flow.go(Step.Biometrics)
        } else Field("Password", flow.password, { flow.password = it }, kind = Input.Password, onDone = ::signIn)
        if (insecure) Note("Without https, anyone on your network can see which server you use.")
        ErrorNote(error)
    }
}
