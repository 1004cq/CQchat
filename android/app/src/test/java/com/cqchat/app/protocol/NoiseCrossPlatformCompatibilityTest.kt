package com.cqchat.app.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Cross-platform contract shared with ios/CQchatTests/NoiseXXCompatibilityTests.swift.
 * The zero public key is also recorded in shared/test-vectors/noise-compat-v1.json.
 */
class NoiseCrossPlatformCompatibilityTest {
    @Test
    fun allZeroX25519PublicKeyIsRejectedBeforeHkdf() {
        val privateKey = NoiseXX.genX25519()
        val zeroPublicKey = ByteArray(32)
        val error = assertThrows(NoiseError::class.java) {
            NoiseXX.dh(privateKey, zeroPublicKey)
        }
        assertTrue(error.code == NoiseError.Code.INVALID_KEY)
    }

    @Test
    fun identityBindingMessageMatchesSharedVector() {
        val x25519 = ByteArray(32) { it.toByte() }
        val ed25519 = ByteArray(32) { (it + 32).toByte() }
        val expected = "435163686174206964656e746974792062696e64696e6720763101" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        assertArrayEquals(expected.hexToBytes()!!, IdentityCrypto.identityBindingMessage(x25519, ed25519))
    }

    @Test
    fun threeMessageNoiseXXHandshakeMatchesIosPattern() {
        val initiatorStatic = NoiseXX.genX25519()
        val responderStatic = NoiseXX.genX25519()
        val initiator = NoiseXX(NoiseXX.Role.INITIATOR, initiatorStatic)
        val responder = NoiseXX(NoiseXX.Role.RESPONDER, responderStatic)

        val message1 = initiator.initiatorWrite1("m1".toByteArray())
        assertTrue(responder.responderRead1(message1).contentEquals("m1".toByteArray()))
        val message2 = responder.responderWrite2("m2".toByteArray())
        assertTrue(initiator.initiatorRead2(message2).contentEquals("m2".toByteArray()))
        val message3 = initiator.initiatorWrite3("m3".toByteArray())
        assertTrue(responder.responderRead3(message3).contentEquals("m3".toByteArray()))

        assertTrue(initiator.completed)
        assertTrue(responder.completed)
        val fromInitiator = initiator.encrypt("android-to-ios".toByteArray())
        assertArrayEquals("android-to-ios".toByteArray(), responder.decrypt(fromInitiator))
        val fromResponder = responder.encrypt("ios-to-android".toByteArray())
        assertArrayEquals("ios-to-android".toByteArray(), initiator.decrypt(fromResponder))
    }
}
