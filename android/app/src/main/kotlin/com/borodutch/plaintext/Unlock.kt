package com.borodutch.plaintext

import android.app.KeyguardManager
import android.content.Intent
import android.net.Uri
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowForward
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import uniffi.plaintext_ffi.PlaintextException

/** One strong-biometric prompt; on success the stored sessions open (the Keystore key allows a few seconds). */
fun promptBiometrics(
    activity: FragmentActivity,
    title: String,
    subtitle: String? = null,
    negative: String = "Use password",
    onNegative: () -> Unit = {},
    onSuccess: () -> Unit,
) {
    val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess()
        override fun onAuthenticationError(code: Int, message: CharSequence) {
            if (code == BiometricPrompt.ERROR_NEGATIVE_BUTTON) onNegative()
        }
    })
    prompt.authenticate(
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .apply { if (subtitle != null) setSubtitle(subtitle) }
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setNegativeButtonText(negative)
            .build(),
    )
}

/** The phone's owner: fingerprint, face or the screen lock PIN. No key is opened, so a weak biometric is enough. */
fun confirmOwner(activity: FragmentActivity, title: String, onSuccess: () -> Unit) {
    BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess()
    }).authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(title).setAllowedAuthenticators(BIOMETRIC_WEAK or DEVICE_CREDENTIAL).build())
}

/** Biometrics right away; a password below as the fallback. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UnlockScreen() {
    val context = LocalContext.current
    val activity = context as FragmentActivity
    val model = context.model
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var accountId by remember { mutableStateOf(model.lockedAccounts.firstOrNull()?.id ?: "") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var signingIn by rememberSaveable { mutableStateOf(false) }
    var menu by remember { mutableStateOf(false) }
    val target = model.known(accountId) ?: model.lockedAccounts.firstOrNull()
    val canBiometric = model.vault.biometrics && model.vault.anySession() && Vault.biometricsAvailable(context)

    fun biometric() = promptBiometrics(activity, "Unlock your vaults") { model.unlockWithStoredSessions() }
    fun unlock() {
        val k = target ?: return
        if (password.isEmpty()) return
        busy = true
        error = null
        val pw = password
        scope.launch {
            try {
                model.unlock(k, pw)
                password = ""
            } catch (_: PlaintextException.KeyNeeded) {
                password = ""
            } catch (e: Exception) {
                error = errorText(e)
            } finally {
                busy = false
            }
        }
    }
    // Prompt whenever the app comes to the front locked (also right after the phone itself is unlocked).
    val owner = androidx.compose.ui.platform.LocalLifecycleOwner.current
    androidx.compose.runtime.DisposableEffect(owner) {
        val o = androidx.lifecycle.LifecycleEventObserver { _, e ->
            if (e == androidx.lifecycle.Lifecycle.Event.ON_START && canBiometric && !model.unlocking && !signingIn) biometric()
        }
        owner.lifecycle.addObserver(o)
        onDispose { owner.lifecycle.removeObserver(o) }
    }

    // A lock ends what the owner's check allowed, and closes the sign-in.
    LaunchedEffect(model.ownerChecked) { if (!model.ownerChecked) signingIn = false }
    if (signingIn) {
        Onboarding(adding = true, onClose = { signingIn = false; model.endOwnerCheck() })
        return
    }

    Column(
        Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Spacer(Modifier.weight(1f))
        Wordmark(36.sp)
        if (canBiometric) {
            TextButton(onClick = ::biometric, enabled = !model.unlocking) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (model.unlocking) CircularProgressIndicator(Modifier.size(52.dp)) else Icon(Icons.Rounded.Fingerprint, null, Modifier.size(56.dp), tint = P.accent)
                    Text("Unlock with fingerprint", color = P.accent, style = MaterialTheme.typography.titleMedium)
                }
            }
        }
        Column(Modifier.widthIn(max = 380.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            if (model.known.size > 1) {
                ExposedDropdownMenuBox(expanded = menu, onExpandedChange = { menu = it }) {
                    OutlinedTextField(
                        value = target?.name ?: "", onValueChange = {}, readOnly = true, label = { Text("Account") },
                        modifier = Modifier.fillMaxWidth().menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable),
                    )
                    ExposedDropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        model.lockedAccounts.forEach { k ->
                            DropdownMenuItem(text = { Text(k.name) }, onClick = { accountId = k.id; menu = false })
                        }
                    }
                }
            }
            if (model.keyPage != null) KeyStep { model.finishUnlock(it) }
            else Field(
                if (model.known.size > 1) "Password for ${target?.username ?: ""}" else "Password", password, { password = it },
                kind = Input.Password, onDone = ::unlock,
                trailing = {
                    if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
                    else IconButton(onClick = ::unlock, enabled = password.isNotEmpty()) { Icon(Icons.AutoMirrored.Rounded.ArrowForward, "Unlock", tint = P.accent) }
                },
            )
            ErrorNote(error)
        }
        Spacer(Modifier.weight(1f))
        // Only after the owner's fingerprint, face or PIN: otherwise anyone holding the phone could add an account and reach Settings.
        // Not on a phone without a screen lock: signing out of every account there brings back first run.
        if (context.getSystemService(KeyguardManager::class.java).isDeviceSecure) TextButton(onClick = {
            confirmOwner(activity, "Confirm it's you to add an account") { model.ownerConfirmed(); signingIn = true }
        }) { Text("Sign in with your Emergency Kit", color = P.muted) }
    }
}

/**
 * A sign-in waiting for the account's security key (DESIGN "Signing in with a security key"): the server's page in the
 * browser asks the key (held to the phone, or plugged in), then Continue finishes here with [finish]. Or a recovery code.
 */
@Composable
fun KeyStep(finish: suspend (recovery: String?) -> Unit) {
    val context = LocalContext.current
    val model = context.model
    val scope = rememberCoroutineScope()
    var code by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("This account needs your security key to sign in on this device.", style = MaterialTheme.typography.titleMedium)
        SecondaryButton("Approve with my security key", {
            val page = model.keyPage ?: return@SecondaryButton
            model.external = true
            runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(page))) }
        })
        Text(
            "That opens a page on your server in the browser, which asks your key: hold it to the phone or plug it in. Then come back here and continue. This phone won't ask again.",
            color = P.muted, style = MaterialTheme.typography.bodySmall,
        )
        Field("Or a recovery code", code, { code = it }, kind = Input.Secret, revealed = true)
        ErrorNote(error)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            TextButton(onClick = { model.cancelKeyStep() }, enabled = !busy) { Text("Cancel") }
            PrimaryButton("Continue", {
                busy = true
                error = null
                scope.launch {
                    try {
                        finish(code.trim().ifEmpty { null })
                        model.keyPage = null
                    } catch (e: Exception) {
                        error = errorText(e)
                    } finally {
                        busy = false
                    }
                }
            }, busy = busy)
        }
    }
}
