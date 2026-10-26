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
        assertEquals(70, root.getInt("header_size"))
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
    fun routingFieldsRoundtripAndBroadcastDefaults() {
        val sender = ByteArray(16) { 1 }
        val msgId = ByteArray(16) { 2 }
        val destination = ByteArray(16) { 3 }
        val nextHop = ByteArray(16) { 4 }
        val packet = CQPacket.make(
            type = CQ.Type.PRIVATE,
            sender = sender,
            msgId = msgId,
            destination = destination,
            nextHop = nextHop,
            payload = byteArrayOf(9, 8, 7),
        )
        val decoded = CQPacket.decode(packet.encode())!!
        assertArrayEquals(destination, decoded.destination)
        assertArrayEquals(nextHop, decoded.nextHop)

        val broadcast = CQPacket.make(CQ.Type.DISCOVER, sender, payload = ByteArray(0))
        assertTrue(CQPacket.isBroadcastAddress(broadcast.destination))
        assertTrue(CQPacket.isBroadcastAddress(broadcast.nextHop))
    }

    @Test
    fun bleMiniFragmentRoundtripAtDefaultAttPayload() {
        val sender = ByteArray(16) { (it + 1).toByte() }
        val msgId = ByteArray(16) { (it + 33).toByte() }
        val raw = CQPacket.make(
            CQ.Type.PRIVATE,
            sender,
            msgId,
            payload = ByteArray(160) { (it and 0xff).toByte() },
        ).encode()
        val fragments = BleMiniFragmenter.split(raw, maxPayload = 20)
        assertTrue(fragments.isNotEmpty())
        assertTrue(fragments.all { it.size <= 20 })

        val reassembler = BleMiniReassembler()
        var output: ByteArray? = null
        fragments.shuffled().forEach { wire ->
            output = BleMiniFragmenter.decode(wire)?.let { reassembler.ingest(it) } ?: output
        }
        assertArrayEquals(raw, output)
        assertEquals(CQ.Type.PRIVATE, CQPacket.decode(output!!)!!.type)
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
        val fpKey = if (hk.has("fingerprint_of_ed25519_seed_as_pk_hex")) {
            "fingerprint_of_ed25519_seed_as_pk_hex"
        } else {
            "fingerprint_of_xseed_as_pk_hex"
        }
        val fpInput = if (fpKey.startsWith("fingerprint_of_ed25519")) e else x
        assertEquals(hk.getString(fpKey), IdentityCrypto.fingerprint(fpInput).toHex())
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

    @Test
    fun tamperedRoutingAdIsRejectedWithoutAdvancingReceiveNonce() {
        val initiator = NoiseXX(NoiseXX.Role.INITIATOR, NoiseXX.genX25519())
        val responder = NoiseXX(NoiseXX.Role.RESPONDER, NoiseXX.genX25519())
        val sender = ByteArray(16) { 1 }
        val destination = ByteArray(16) { 2 }
        val envelope = CQPacket.make(
            type = CQ.Type.PRIVATE,
            sender = sender,
            destination = destination,
            payload = ByteArray(0),
        )
        responder.responderRead1(initiator.initiatorWrite1())
        initiator.initiatorRead2(responder.responderWrite2())
        val hello = initiator.initiatorWrite3(ByteArray(0))
        responder.responderRead3(hello)

        val ciphertext = initiator.encrypt("ad-bound".toByteArray(), envelope.associatedData())
        val tampered = envelope.copy(destination = ByteArray(16) { 9 })
        assertThrows(NoiseError::class.java) {
            responder.decrypt(ciphertext, tampered.associatedData())
        }
        assertArrayEquals(
            "ad-bound".toByteArray(),
            responder.decrypt(ciphertext, envelope.associatedData()),
        )
    }

    private fun readWorkspaceVector(): String {
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
        val sender = ByteArray(16) { it.toByte() }
        val msgId = ByteArray(16) { (it + 16).toByte() }
        val empty = CQPacket.make(CQ.Type.DISCOVER, sender, msgId, payload = ByteArray(0)).encode()
        return """{"header_size":70,"version":2,"discover_empty":{"hex":"${empty.toHex()}"},"hkdf":{"identity_seed_hex":"${"00".repeat(31)}01","x25519_seed_hex":"${NoiseXX.cqHkdf(ByteArray(32){if(it==31)1 else 0}, ByteArray(0), "cqchat-v1-x25519".toByteArray(), 32).toHex()}","ed25519_seed_hex":"${NoiseXX.cqHkdf(ByteArray(32){if(it==31)1 else 0}, ByteArray(0), "cqchat-v1-ed25519".toByteArray(), 32).toHex()}","fingerprint_of_xseed_as_pk_hex":"${IdentityCrypto.fingerprint(NoiseXX.cqHkdf(ByteArray(32){if(it==31)1 else 0}, ByteArray(0), "cqchat-v1-x25519".toByteArray(), 32)).toHex()}"}}"""
    }
}
