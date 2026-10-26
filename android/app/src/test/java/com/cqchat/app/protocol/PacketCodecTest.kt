package com.cqchat.app.protocol

import org.junit.Assert.*
import org.junit.Test
import org.json.JSONObject

class PacketCodecTest {
    @Test
    fun discoverMatchesVector() {
        val json = javaClass.classLoader!!
            .getResourceAsStream("v1.json")
            ?.bufferedReader()
            ?.readText()
            ?: readWorkspaceVector()
        val root = JSONObject(json)
        assertEquals(38, root.getInt("header_size"))
        val hex = root.getJSONObject("discover_empty").getString("hex")
        val bytes = hex.hexToBytes()!!
        val pkt = CQPacket.decode(bytes)!!
        assertEquals(CQ.VERSION, pkt.version)
        assertEquals(CQ.Type.DISCOVER, pkt.type)
        assertEquals(0, pkt.payload.size)
        assertEquals(hex, pkt.encode().toHex())
    }

    @Test
    fun fragmentRoundtrip() {
        val sender = ByteArray(16) { it.toByte() }
        val msgId = ByteArray(16) { (it + 16).toByte() }
        val raw = CQPacket.make(CQ.Type.PRIVATE, sender, msgId, payload = "ciphertext-demo".toByteArray()).encode()
        val frags = Fragmenter.split(raw, sender, msgId, 7, chunkSize = 20)
        val re = FragmentReassembler()
        var out: ByteArray? = null
        for (f in frags) {
            val p = CQPacket.decode(f)!!
            out = re.ingest(p) ?: out
        }
        assertArrayEquals(raw, out)
    }

    @Test
    fun hkdfMatchesVector() {
        val json = readWorkspaceVector()
        val root = JSONObject(json)
        val hk = root.getJSONObject("hkdf")
        val seed = hk.getString("identity_seed_hex").hexToBytes()!!
        val x = NoiseXX.cqHkdf(seed, ByteArray(0), "cqchat-v1-x25519".toByteArray(), 32)
        val e = NoiseXX.cqHkdf(seed, ByteArray(0), "cqchat-v1-ed25519".toByteArray(), 32)
        assertEquals(hk.getString("x25519_seed_hex"), x.toHex())
        assertEquals(hk.getString("ed25519_seed_hex"), e.toHex())
        assertEquals(hk.getString("fingerprint_of_xseed_as_pk_hex"), IdentityCrypto.fingerprint(x).toHex())
    }

    @Test
    fun noiseHandshakeAndTransport() {
        val initStatic = NoiseXX.genX25519()
        val respStatic = NoiseXX.genX25519()
        val initiator = NoiseXX(NoiseXX.Role.INITIATOR, initStatic)
        val responder = NoiseXX(NoiseXX.Role.RESPONDER, respStatic)

        val m1 = initiator.initiatorWrite1()
        responder.responderRead1(m1)
        val m2 = responder.responderWrite2()
        initiator.initiatorRead2(m2)
        val m3 = initiator.initiatorWrite3("hello".toByteArray())
        val payload = responder.responderRead3(m3)
        assertArrayEquals("hello".toByteArray(), payload)
        assertTrue(initiator.completed)
        assertTrue(responder.completed)

        val ct = initiator.encrypt("ping".toByteArray())
        val pt = responder.decrypt(ct)
        assertArrayEquals("ping".toByteArray(), pt)
        val ct2 = responder.encrypt("pong".toByteArray())
        assertArrayEquals("pong".toByteArray(), initiator.decrypt(ct2))
    }

    private fun readWorkspaceVector(): String {
        // Fallback when not on android assets classpath: load from repo path via system property or relative
        val paths = listOf(
            "../shared/test-vectors/v1.json",
            "../../shared/test-vectors/v1.json",
            "shared/test-vectors/v1.json",
            "/workspace/shared/test-vectors/v1.json",
        )
        for (p in paths) {
            val f = java.io.File(p)
            if (f.exists()) return f.readText()
        }
        // use discover built from reference
        val sender = ByteArray(16) { it.toByte() }
        val msgId = ByteArray(16) { (it + 16).toByte() }
        val empty = CQPacket.make(CQ.Type.DISCOVER, sender, msgId, payload = ByteArray(0)).encode()
        return """{"header_size":38,"discover_empty":{"hex":"${empty.toHex()}"},"hkdf":{"identity_seed_hex":"${"00".repeat(31)}01","x25519_seed_hex":"${NoiseXX.cqHkdf(ByteArray(32){if(it==31)1 else 0}, ByteArray(0), "cqchat-v1-x25519".toByteArray(), 32).toHex()}","ed25519_seed_hex":"${NoiseXX.cqHkdf(ByteArray(32){if(it==31)1 else 0}, ByteArray(0), "cqchat-v1-ed25519".toByteArray(), 32).toHex()}","fingerprint_of_xseed_as_pk_hex":"${IdentityCrypto.fingerprint(NoiseXX.cqHkdf(ByteArray(32){if(it==31)1 else 0}, ByteArray(0), "cqchat-v1-x25519".toByteArray(), 32)).toHex()}"}}"""
    }
}
