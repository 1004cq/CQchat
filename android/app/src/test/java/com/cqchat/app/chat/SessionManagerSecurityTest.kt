package com.cqchat.app.chat

import com.cqchat.app.protocol.NoiseXX
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class SessionManagerSecurityTest {
    @Test
    fun allZeroX25519PublicKeyIsRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            NoiseXX.dh(NoiseXX.genX25519(), ByteArray(32))
        }
    }

    @Test
    fun clearMakesSessionManagerIrreversiblyClosed() {
        val manager = SessionManager(NoiseXX.genX25519())
        manager.clear()
        assertNull(manager.handshake(ByteArray(16)))
        assertThrows(IllegalStateException::class.java) {
            manager.begin(NoiseXX.Role.INITIATOR, ByteArray(16))
        }
    }

    @Test
    fun conflictingHandshakeRolesDoNotReuseTheOldNoiseState() {
        val manager = SessionManager(NoiseXX.genX25519())
        val temp = ByteArray(16) { 3 }
        val responder = manager.begin(NoiseXX.Role.RESPONDER, temp)
        val initiator = manager.begin(NoiseXX.Role.INITIATOR, temp)
        assertNotSame(responder, initiator)
    }
}
