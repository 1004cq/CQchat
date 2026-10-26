package com.cqchat.app.crypto

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.cqchat.app.protocol.CQ
import com.cqchat.app.protocol.IdentityCrypto
import com.cqchat.app.protocol.NoiseXX
import com.cqchat.app.protocol.toHex
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * First launch: CSPRNG 32-byte identity_seed, wrapped with AndroidKeyStore AES key.
 * Derives X25519 + Ed25519 via HKDF info labels from PROTOCOL.md.
 */
class IdentityStore(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("cqchat_identity", Context.MODE_PRIVATE)
    private val appPrefs: SharedPreferences =
        context.getSharedPreferences("cqchat_app", Context.MODE_PRIVATE)

    var seed: ByteArray = ByteArray(0)
        private set
    var x25519Private: ByteArray = ByteArray(0)
        private set
    var x25519Public: ByteArray = ByteArray(0)
        private set
    var ed25519Private: ByteArray = ByteArray(0)
        private set
    var ed25519Public: ByteArray = ByteArray(0)
        private set
    var fingerprint: ByteArray = ByteArray(0)
        private set
    var fingerprintHex: String = ""
        private set

    init {
        deriveFrom(loadOrCreateSeed())
    }

    var nickname: String
        get() = appPrefs.getString("nickname", "anon") ?: "anon"
        set(v) { appPrefs.edit().putString("nickname", v).apply() }

    fun qrPayload(): String = CQ.QR_PREFIX + fingerprintHex

    fun parseQR(s: String): ByteArray? {
        val t = s.trim()
        if (!t.startsWith(CQ.QR_PREFIX)) return null
        return t.removePrefix(CQ.QR_PREFIX).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            .takeIf { it.size == 16 }
    }

    fun isVerified(fp: ByteArray): Boolean =
        verifiedSet().contains(fp.toHex())

    fun markVerified(fp: ByteArray) {
        val set = verifiedSet().toMutableSet()
        set.add(fp.toHex())
        appPrefs.edit().putStringSet("verified", set).apply()
    }

    fun isFavorite(fp: ByteArray): Boolean =
        favoriteSet().contains(fp.toHex())

    fun setFavorite(on: Boolean, fp: ByteArray) {
        val set = favoriteSet().toMutableSet()
        if (on) set.add(fp.toHex()) else set.remove(fp.toHex())
        appPrefs.edit().putStringSet("favorites", set).apply()
    }

    fun favoriteFingerprints(): Set<String> = favoriteSet()

    /** Delete Keystore wrap + prefs, then mint a fresh identity_seed. */
    fun wipeAndRegenerate() {
        wipeStorage()
        deriveFrom(loadOrCreateSeed())
    }

    fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(ed25519Private, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun verify(pk: ByteArray, message: ByteArray, sig: ByteArray): Boolean {
        return try {
            val signer = Ed25519Signer()
            signer.init(false, org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(pk, 0))
            signer.update(message, 0, message.size)
            signer.verifySignature(sig)
        } catch (_: Exception) {
            false
        }
    }

    private fun deriveFrom(seedBytes: ByteArray) {
        seed = seedBytes
        val xSeed = NoiseXX.cqHkdf(seed, ByteArray(0), "cqchat-v1-x25519".toByteArray(), 32)
        val eSeed = NoiseXX.cqHkdf(seed, ByteArray(0), "cqchat-v1-ed25519".toByteArray(), 32)
        x25519Private = xSeed
        x25519Public = X25519PrivateKeyParameters(xSeed, 0).generatePublicKey().encoded
        ed25519Private = eSeed
        ed25519Public = Ed25519PrivateKeyParameters(eSeed, 0).generatePublicKey().encoded
        fingerprint = IdentityCrypto.fingerprint(ed25519Public)
        fingerprintHex = fingerprint.toHex()
    }

    private fun wipeStorage() {
        prefs.edit().clear().apply()
        appPrefs.edit().clear().apply()
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
        } catch (_: Exception) {
        }
    }

    private fun verifiedSet(): Set<String> =
        appPrefs.getStringSet("verified", emptySet()) ?: emptySet()

    private fun favoriteSet(): Set<String> =
        appPrefs.getStringSet("favorites", emptySet()) ?: emptySet()

    private fun loadOrCreateSeed(): ByteArray {
        val wrapped = prefs.getString(PREF_WRAPPED, null)
        if (wrapped != null) {
            return unwrap(Base64.decode(wrapped, Base64.DEFAULT))
        }
        val seed = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val enc = wrap(seed)
        prefs.edit().putString(PREF_WRAPPED, Base64.encodeToString(enc, Base64.DEFAULT)).apply()
        return seed
    }

    private fun aesKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) {
            return (ks.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return gen.generateKey()
    }

    private fun wrap(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, aesKey())
        val iv = c.iv
        val ct = c.doFinal(plain)
        return iv + ct
    }

    private fun unwrap(blob: ByteArray): ByteArray {
        val iv = blob.copyOfRange(0, 12)
        val ct = blob.copyOfRange(12, blob.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, aesKey(), GCMParameterSpec(128, iv))
        return c.doFinal(ct)
    }

    companion object {
        private const val KEY_ALIAS = "cqchat_identity_wrap"
        private const val PREF_WRAPPED = "seed_wrapped_v1"
    }
}
