package com.cqchat.app.protocol

import com.cqchat.app.chat.DedupCache
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NoiseAttackResistanceTest {
    @Test
    fun transportCiphertextReplayIsRejected() {
        val (initiator, responder) = completedSession()
        val ciphertext = initiator.encrypt("once-only".toByteArray())

        assertArrayEquals("once-only".toByteArray(), responder.decrypt(ciphertext))
        assertThrows(Exception::class.java) {
            responder.decrypt(ciphertext.copyOf())
        }
    }

    @Test
    fun failedAeadDoesNotConsumeReceiveNonce() {
        val key = ByteArray(32) { 0x42 }
        val sender = CipherState(key)
        val receiver = CipherState(key)
        val plaintext = "must-survive-an-invalid-packet".toByteArray()
        val ad = "header".toByteArray()
        val valid = sender.encrypt(plaintext, ad)

        val tampered = valid.copyOf().also {
            it[it.lastIndex] = (it[it.lastIndex].toInt() xor 1).toByte()
        }
        val error = assertThrows(NoiseError::class.java) {
            receiver.decrypt(tampered, ad)
        }
        assertTrue(error.code == NoiseError.Code.DECRYPT_FAILED)

        assertArrayEquals(plaintext, receiver.decrypt(valid, ad))
    }

    @Test
    fun malformedCiphertextMapsToProtocolError() {
        val receiver = CipherState(ByteArray(32) { 0x42 })
        val error = assertThrows(NoiseError::class.java) {
            receiver.decrypt(ByteArray(15), ByteArray(0))
        }
        assertTrue(error.code == NoiseError.Code.MALFORMED_MESSAGE)
    }

    @Test
    fun handshakeStep1ReplayCannotAdvanceResponderTwice() {
        val initiator = NoiseXX(NoiseXX.Role.INITIATOR, NoiseXX.genX25519())
        val responder = NoiseXX(NoiseXX.Role.RESPONDER, NoiseXX.genX25519())
        val message1 = initiator.initiatorWrite1()

        responder.responderRead1(message1)
        assertThrows(Exception::class.java) {
            responder.responderRead1(message1.copyOf())
        }
    }

    @Test
    fun handshakeStep2AndStep3ReplaysAreRejected() {
        val initiator = NoiseXX(NoiseXX.Role.INITIATOR, NoiseXX.genX25519())
        val responder = NoiseXX(NoiseXX.Role.RESPONDER, NoiseXX.genX25519())
        responder.responderRead1(initiator.initiatorWrite1())
        val message2 = responder.responderWrite2()
        initiator.initiatorRead2(message2)
        assertThrows(Exception::class.java) {
            initiator.initiatorRead2(message2.copyOf())
        }

        val message3 = initiator.initiatorWrite3()
        responder.responderRead3(message3)
        assertThrows(Exception::class.java) {
            responder.responderRead3(message3.copyOf())
        }
    }

    @Test
    fun tamperedHandshakeStep2IsRejectedBeforeSessionCompletion() {
        val initiator = NoiseXX(NoiseXX.Role.INITIATOR, NoiseXX.genX25519())
        val responder = NoiseXX(NoiseXX.Role.RESPONDER, NoiseXX.genX25519())
        responder.responderRead1(initiator.initiatorWrite1())
        val message2 = responder.responderWrite2()
        message2[message2.lastIndex] = (message2[message2.lastIndex].toInt() xor 1).toByte()

        assertThrows(Exception::class.java) {
            initiator.initiatorRead2(message2)
        }
        assertFalse(initiator.completed)
    }

    @Test
    fun tamperedHandshakeStep3IsRejectedBeforeResponderCompletion() {
        val initiator = NoiseXX(NoiseXX.Role.INITIATOR, NoiseXX.genX25519())
        val responder = NoiseXX(NoiseXX.Role.RESPONDER, NoiseXX.genX25519())
        responder.responderRead1(initiator.initiatorWrite1())
        initiator.initiatorRead2(responder.responderWrite2())
        val message3 = initiator.initiatorWrite3("binding".toByteArray())
        message3[message3.lastIndex] = (message3[message3.lastIndex].toInt() xor 1).toByte()

        assertThrows(Exception::class.java) {
            responder.responderRead3(message3)
        }
        assertFalse(responder.completed)
    }

    @Test
    fun identityBindingSignatureCannotBeReusedWithAnotherX25519Key() {
        val edPrivate = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(
            ByteArray(32) { (it + 1).toByte() }, 0
        )
        val edPublic = edPrivate.generatePublicKey().encoded
        val x25519 = ByteArray(32) { (it + 33).toByte() }
        val signature = sign(edPrivate, IdentityCrypto.identityBindingMessage(x25519, edPublic))
        val changedX25519 = x25519.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

        assertTrue(verify(edPublic, IdentityCrypto.identityBindingMessage(x25519, edPublic), signature))
        assertFalse(verify(edPublic, IdentityCrypto.identityBindingMessage(changedX25519, edPublic), signature))
    }

    @Test
    fun packetMessageIdReplayIsDeduplicated() {
        val cache = DedupCache()
        val msgId = ByteArray(16) { (it + 9).toByte() }
        assertFalse(cache.seen(msgId))
        assertTrue(cache.seen(msgId.copyOf()))
    }

    private fun completedSession(): Pair<NoiseXX, NoiseXX> {
        val initiator = NoiseXX(NoiseXX.Role.INITIATOR, NoiseXX.genX25519())
        val responder = NoiseXX(NoiseXX.Role.RESPONDER, NoiseXX.genX25519())
        responder.responderRead1(initiator.initiatorWrite1())
        initiator.initiatorRead2(responder.responderWrite2())
        responder.responderRead3(initiator.initiatorWrite3())
        return initiator to responder
    }

    private fun sign(
        privateKey: org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters,
        message: ByteArray,
    ): ByteArray = org.bouncycastle.crypto.signers.Ed25519Signer().run {
        init(true, privateKey)
        update(message, 0, message.size)
        generateSignature()
    }

    private fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        org.bouncycastle.crypto.signers.Ed25519Signer().run {
            init(false, org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(publicKey, 0))
            update(message, 0, message.size)
            verifySignature(signature)
        }
}
