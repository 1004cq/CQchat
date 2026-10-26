package com.cqchat.app.protocol

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityBindingTest {
    @Test
    fun ed25519SignatureBindsTheExactX25519PublicKey() {
        val edPrivate = Ed25519PrivateKeyParameters(ByteArray(32) { (it + 1).toByte() }, 0)
        val edPublic = edPrivate.generatePublicKey().encoded
        val x25519 = ByteArray(32) { (it + 33).toByte() }
        val message = IdentityCrypto.identityBindingMessage(x25519, edPublic)

        val signer = Ed25519Signer().apply {
            init(true, edPrivate)
            update(message, 0, message.size)
        }
        val signature = signer.generateSignature()

        val verifier = Ed25519Signer().apply {
            init(false, org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(edPublic, 0))
            update(message, 0, message.size)
        }
        assertTrue(verifier.verifySignature(signature))

        val tamperedX25519 = x25519.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val tamperedMessage = IdentityCrypto.identityBindingMessage(tamperedX25519, edPublic)
        val tamperedVerifier = Ed25519Signer().apply {
            init(false, org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(edPublic, 0))
            update(tamperedMessage, 0, tamperedMessage.size)
        }
        assertFalse(tamperedVerifier.verifySignature(signature))
    }
}
