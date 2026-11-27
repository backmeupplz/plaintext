package com.borodutch.plaintext

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.os.PersistableBundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import org.json.JSONArray
import org.json.JSONObject
import uniffi.plaintext_ffi.UnlockData
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** An account this device knows, signed in or not. */
data class KnownAccount(val id: String, val server: String, val username: String) {
    /** `vault.example.com:8443` for `https://vault.example.com:8443`. */
    val host: String get() = server.substringAfter("://")
    val name: String get() = "$username@$host"
}

/**
 * What this device keeps, in its no-backup folder (backups and device transfers are off in the manifest too):
 * - the known accounts (id, server, username), in the clear;
 * - each account's Secret Key, sealed by a Keystore AES key that needs no authentication (like the iOS
 *   keychain's "after first unlock"), so the password alone unlocks on this device;
 * - each account's session token and Account Key, sealed to a Keystore RSA key whose private half only
 *   works for a few seconds after a strong biometric check and dies when a new fingerprint or face is
 *   enrolled. Sealing needs only the public half, so saving a session never prompts; one prompt opens
 *   every account. The password itself is never stored.
 */
class Vault(private val context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("plaintext", Context.MODE_PRIVATE)
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    var known: List<KnownAccount>
        get() = runCatching {
            val a = JSONArray(prefs.getString("accounts", "[]"))
            (0 until a.length()).map { a.getJSONObject(it).let { o -> KnownAccount(o.getString("id"), o.getString("server"), o.getString("username")) } }
        }.getOrDefault(emptyList())
        set(v) {
            val a = JSONArray()
            v.forEach { a.put(JSONObject().put("id", it.id).put("server", it.server).put("username", it.username)) }
            prefs.edit().putString("accounts", a.toString()).apply()
        }

    // ----- Settings -----
    var autoLockMinutes: Int
        get() = prefs.getInt("autoLockMinutes", 10)
        set(v) = prefs.edit().putInt("autoLockMinutes", v).apply()
    var clipboardSeconds: Int
        get() = prefs.getInt("clipboardSeconds", 90)
        set(v) = prefs.edit().putInt("clipboardSeconds", v).apply()
    var biometrics: Boolean
        get() = prefs.getBoolean("biometrics", true)
        set(v) = prefs.edit().putBoolean("biometrics", v).apply()
    var linkPage: String
        get() = prefs.getString("linkPage", null) ?: ""
        set(v) = prefs.edit().putString("linkPage", v).apply()
    var breachCheck: Boolean
        get() = prefs.getBoolean("breachCheck", false)
        set(v) = prefs.edit().putBoolean("breachCheck", v).apply()
    var sortRecent: Boolean
        get() = prefs.getBoolean("sortRecent", false)
        set(v) = prefs.edit().putBoolean("sortRecent", v).apply()
    var recentServers: List<String>
        get() = prefs.getString("recentServers", "")!!.split("\n").filter { it.isNotBlank() }
        set(v) = prefs.edit().putString("recentServers", v.take(5).joinToString("\n")).apply()

    // ----- Secret Keys (device key, no authentication) -----

    fun saveSecretKey(account: String, sk: String) {
        prefs.edit().putString("sk.$account", seal(deviceKey(), sk.toByteArray())).apply()
    }

    fun secretKey(account: String): String? = runCatching {
        prefs.getString("sk.$account", null)?.let { String(open(deviceKey(), it)) }
    }.getOrNull()

    // ----- Sessions (biometric key) -----

    fun hasSession(account: String) = prefs.contains("session.$account")
    fun anySession() = known.any { hasSession(it.id) }

    /** Seal a session to the biometric key's public half: no prompt. */
    fun saveSession(account: String, u: UnlockData) {
        val body = JSONObject()
            .put("token", u.token)
            .put("accountId", b64(u.accountId))
            .put("accountKey", b64(u.accountKey))
            .toString().toByteArray()
        val dataKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val rsa = Cipher.getInstance(RSA).apply { init(Cipher.ENCRYPT_MODE, bioPublic(), OAEP) }
        val wrapped = rsa.doFinal(dataKey)
        val sealed = seal(SecretKeySpec(dataKey, "AES"), body)
        dataKey.fill(0)
        body.fill(0)
        prefs.edit().putString("session.$account", b64(wrapped) + "." + sealed).apply()
    }

    /**
     * Open stored sessions. Call within a few seconds of a successful BiometricPrompt. Throws
     * [android.security.keystore.KeyPermanentlyInvalidatedException] when biometrics changed since.
     */
    fun sessions(): Map<String, UnlockData> = known.mapNotNull { k -> session(k.id)?.let { k.id to it } }.toMap()

    /** One stored session, under the same rules as [sessions]. */
    fun session(account: String): UnlockData? {
        val key = ks.getKey(BIO, null) as? java.security.PrivateKey ?: return null
        val raw = prefs.getString("session.$account", null) ?: return null
        val (wrapped, sealed) = raw.split(".", limit = 2).let { it[0] to it[1] }
        val rsa = Cipher.getInstance(RSA).apply { init(Cipher.DECRYPT_MODE, key, OAEP) }
        val dataKey = rsa.doFinal(unb64(wrapped))
        val body = open(SecretKeySpec(dataKey, "AES"), sealed)
        dataKey.fill(0)
        val o = JSONObject(String(body))
        body.fill(0)
        return UnlockData(o.getString("token"), unb64(o.getString("accountId")), unb64(o.getString("accountKey")))
    }

    fun forgetSession(account: String) = prefs.edit().remove("session.$account").apply()

    /** Biometrics changed or were turned off: every stored session goes, and so does the key. */
    fun forgetAllSessions() {
        prefs.edit().apply { known.forEach { remove("session.${it.id}") } }.apply()
        runCatching { ks.deleteEntry(BIO) }
    }

    fun forget(account: String) {
        prefs.edit().remove("session.$account").remove("sk.$account").apply()
    }

    // ----- Keys -----

    private fun deviceKey(): SecretKey {
        (ks.getKey(DEVICE, null) as? SecretKey)?.let { return it }
        return strongBoxOrNot { strong ->
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(
                    KeyGenParameterSpec.Builder(DEVICE, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .setIsStrongBoxBacked(strong)
                        .build(),
                )
            }.generateKey()
        }
    }

    /** The biometric key's public half, as a plain key so encrypting happens in software. */
    private fun bioPublic(): java.security.PublicKey {
        // Invalidated by a new enrolment: sessions sealed to it could never open, so start over with a new key.
        // biometricsAvailable() keeps every caller on Android 11 or later.
        if (Build.VERSION.SDK_INT < 30) throw IllegalStateException("biometric unlock needs Android 11")
        if (ks.containsAlias(BIO) && !bioKeyUsable()) forgetAllSessions()
        val cert = ks.getCertificate(BIO) ?: run {
            strongBoxOrNot { strong ->
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").apply {
                    val b = KeyGenParameterSpec.Builder(BIO, KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(2048)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setUserAuthenticationRequired(true)
                        .setInvalidatedByBiometricEnrollment(true)
                        .setIsStrongBoxBacked(strong)
                    b.setUserAuthenticationParameters(AUTH_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    initialize(b.build())
                }.generateKeyPair()
            }
            ks.getCertificate(BIO)
        }
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(cert.publicKey.encoded))
    }

    private fun bioKeyUsable() = try {
        Cipher.getInstance(RSA).init(Cipher.DECRYPT_MODE, ks.getKey(BIO, null) as java.security.PrivateKey, OAEP)
        true
    } catch (_: KeyPermanentlyInvalidatedException) {
        false
    } catch (_: Exception) {
        true // not authenticated right now, which is fine for sealing
    }

    /** StrongBox when the phone has one. */
    private fun <T> strongBoxOrNot(make: (Boolean) -> T): T {
        val has = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (has) {
            try { return make(true) } catch (_: StrongBoxUnavailableException) {}
        }
        return make(false)
    }

    private fun seal(key: SecretKey, data: ByteArray): String {
        val c = Cipher.getInstance(AES)
        if (key is SecretKeySpec) {
            val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
            c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        } else {
            c.init(Cipher.ENCRYPT_MODE, key) // the Keystore picks the IV
        }
        return b64(c.iv) + ":" + b64(c.doFinal(data))
    }

    private fun open(key: SecretKey, s: String): ByteArray {
        val (iv, ct) = s.split(":", limit = 2)
        val c = Cipher.getInstance(AES)
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, unb64(iv)))
        return c.doFinal(unb64(ct))
    }

    companion object {
        private const val DEVICE = "plaintext.device"
        private const val BIO = "plaintext.biometric"
        private const val AUTH_SECONDS = 15
        private const val AES = "AES/GCM/NoPadding"
        private const val RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        private val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
        private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)

        /**
         * A strong fingerprint or face sensor with something enrolled, on Android 11 or later. Before that, a key usable for
         * a few seconds after authenticating also opens with the screen lock PIN and survives a new enrolment.
         */
        fun biometricsAvailable(context: Context) = Build.VERSION.SDK_INT >= 30 && canPrompt(context)

        /** A strong biometric prompt works (on any version): enough for a fresh check before showing a secret. */
        fun canPrompt(context: Context) =
            BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

        /** Why biometric unlock is off, for settings and onboarding copy; null when it's available. */
        fun biometricsMissing(context: Context) = when {
            !canPrompt(context) -> "Set up a fingerprint or face in Android's settings to unlock with it."
            Build.VERSION.SDK_INT < 30 -> "Unlocking with a fingerprint or face needs Android 11 or later."
            else -> null
        }
    }
}

/** Copies marked sensitive (no preview in the clipboard overlay or keyboard), cleared after a while. */
object Clipboard {
    private const val LABEL = "Plaintext"
    private var clearAt = 0L

    fun copy(context: Context, text: String, sensitive: Boolean, seconds: Int, scope: CoroutineScope) {
        val cm = context.getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText(LABEL, text)
        if (sensitive) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE", true)
            }
        }
        cm.setPrimaryClip(clip)
        if (!sensitive || seconds <= 0) return
        val at = System.currentTimeMillis() + seconds * 1000L
        clearAt = at
        scope.launch {
            delay(seconds * 1000L)
            if (clearAt == at) clear(context)
        }
    }

    /**
     * Clear the clipboard unless something else was copied since. In the background Android hides what's on
     * the clipboard, and then it's cleared anyway: a stray clear beats a password left behind.
     */
    fun clear(context: Context) {
        if (clearAt == 0L) return
        clearAt = 0L
        runCatching {
            val cm = context.getSystemService(ClipboardManager::class.java)
            val label = runCatching { cm.primaryClipDescription?.label }.getOrNull()
            if (label == null || label == LABEL) cm.clearPrimaryClip()
        }
    }
}
