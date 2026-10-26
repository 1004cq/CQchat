package com.cqchat.app.transport

import com.cqchat.app.protocol.BleMeshPacketCodec
import com.cqchat.app.protocol.BleMiniFragmenter
import com.cqchat.app.protocol.BleMiniReassembler
import com.cqchat.app.protocol.CQ
import com.cqchat.app.protocol.CQPacket
import com.cqchat.app.protocol.FragmentPayload
import com.cqchat.app.protocol.FragmentReassembler
import com.cqchat.app.protocol.Fragmenter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class BleMeshServiceBoundaryTest {
    private val sender = ByteArray(16) { (it + 1).toByte() }
    private val msgId = ByteArray(16) { (it + 41).toByte() }

    @Test
    fun serviceCodecSupportsDefaultAttPayloadAndOutOfOrderMiniFragments() {
        val raw = packet(payloadSize = 512)
        val wire = BleMeshPacketCodec.split(raw, maxPayload = 20)
        assertTrue(wire.size > 1)
        assertTrue(wire.all { it.size <= 20 })
        assertTrue(wire.all { BleMiniFragmenter.decode(it) != null })

        val reassembler = BleMiniReassembler()
        var result: ByteArray? = null
        wire.shuffled().forEach { frame ->
            result = BleMiniFragmenter.decode(frame)?.let { reassembler.ingest(it) } ?: result
        }
        assertArrayEquals(raw, result)
    }

    @Test
    fun miniReassemblerIsSafeUnderConcurrentOutOfOrderInput() {
        val raw = packet(payloadSize = 1_024)
        val wire = BleMeshPacketCodec.split(raw, maxPayload = 20)
        val shuffled = wire.shuffled()
        val reassembler = BleMiniReassembler()
        val results = Collections.synchronizedList(mutableListOf<ByteArray>())
        val executor = Executors.newFixedThreadPool(8)
        val latch = CountDownLatch(shuffled.size)
        try {
            shuffled.forEach { frame ->
                executor.execute {
                    try {
                        BleMiniFragmenter.decode(frame)?.let { reassembler.ingest(it) }?.let(results::add)
                    } finally {
                        latch.countDown()
                    }
                }
            }
            assertTrue(latch.await(5, TimeUnit.SECONDS))
        } finally {
            executor.shutdownNow()
        }
        assertEquals(1, results.size)
        assertArrayEquals(raw, results.single())
    }

    @Test
    fun duplicateFragmentsDoNotIncreaseReassembledSize() {
        val raw = packet(payloadSize = 240)
        val wire = BleMeshPacketCodec.split(raw, maxPayload = 20)
        val reassembler = BleMiniReassembler()
        val first = BleMiniFragmenter.decode(wire.first())!!
        repeat(20) { assertNull(reassembler.ingest(first)) }
        var result: ByteArray? = null
        wire.drop(1).forEach { frame ->
            result = BleMiniFragmenter.decode(frame)?.let { reassembler.ingest(it) } ?: result
        }
        assertArrayEquals(raw, result)
    }

    @Test
    fun malformedMiniHeadersAreRejectedWithoutAllocation() {
        assertNull(BleMiniFragmenter.decode(ByteArray(BleMiniFragmenter.HEADER_SIZE - 1)))
        val token = ByteArray(8) { 7 }
        val zeroTotal = BleMiniFragmenter.encode(0, 1, token, byteArrayOf(1)).also { it[5] = 0; it[6] = 0 }
        assertNull(BleMiniFragmenter.decode(zeroTotal))
        val badIndex = BleMiniFragmenter.encode(0, 1, token, byteArrayOf(1)).also { it[3] = 0; it[4] = 1 }
        assertNull(BleMiniFragmenter.decode(badIndex))
        assertNull(BleMiniFragmenter.decode(byteArrayOf('C'.code.toByte(), 'Q'.code.toByte(), 99)))
    }

    @Test
    fun miniPendingTableIsBoundedForManyUniqueAttackers() {
        val reassembler = BleMiniReassembler()
        repeat(CQ.MAX_PENDING_REASSEMBLIES + 64) { n ->
            val token = ByteArray(8) { i -> (n * 17 + i).toByte() }
            reassembler.ingest(BleMiniFragmenter.decode(BleMiniFragmenter.encode(0, 2, token, byteArrayOf(1)))!!)
        }
        val field = BleMiniReassembler::class.java.getDeclaredField("pending")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val pending = field.get(reassembler) as Map<*, *>
        assertTrue(pending.size <= CQ.MAX_PENDING_REASSEMBLIES)
    }

    @Test
    fun legacyFragmentReassemblerHandlesConcurrentShuffledInput() {
        val raw = packet(payloadSize = 320)
        val fragments = Fragmenter.split(raw, sender, msgId, ttl = 3, chunkSize = 17)
            .mapNotNull { CQPacket.decode(it) }
            .shuffled()
        val reassembler = FragmentReassembler()
        val results = Collections.synchronizedList(mutableListOf<ByteArray>())
        val executor = Executors.newFixedThreadPool(6)
        val latch = CountDownLatch(fragments.size)
        try {
            fragments.forEach { fragment ->
                executor.execute {
                    try {
                        reassembler.ingest(fragment)?.let(results::add)
                    } finally {
                        latch.countDown()
                    }
                }
            }
            assertTrue(latch.await(5, TimeUnit.SECONDS))
        } finally {
            executor.shutdownNow()
        }
        assertEquals(1, results.size)
        assertArrayEquals(raw, results.single())
    }

    @Test
    fun oversizedAndInvalidPacketsAreRejectedBeforeFragmentAllocation() {
        val oversized = ByteArray(CQ.MAX_REASSEMBLY_BYTES + 1)
        assertTrue(BleMeshPacketCodec.split(oversized, maxPayload = 20).isEmpty())
        assertTrue(BleMeshPacketCodec.split(byteArrayOf(1, 2, 3), maxPayload = 20).isEmpty())
        assertThrows(IllegalArgumentException::class.java) {
            Fragmenter.split(oversized, sender, msgId, ttl = 1, chunkSize = 20)
        }
        assertThrows(IllegalArgumentException::class.java) {
            Fragmenter.split(packet(32), sender, msgId, ttl = 1, chunkSize = 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            BleMeshPacketCodec.split(packet(32), maxPayload = 0)
        }

        val invalidFragmentPayload = byteArrayOf(0, 0, 0, 0, 1)
        val invalidPacket = CQPacket.make(
            type = CQ.Type.FRAGMENT,
            sender = sender,
            msgId = msgId,
            payload = invalidFragmentPayload,
        )
        assertNull(FragmentReassembler().ingest(invalidPacket))
        assertNotNull(FragmentPayload.decode(byteArrayOf(0, 0, 0, 1, 9)))
    }

    private fun packet(payloadSize: Int): ByteArray = CQPacket.make(
        type = CQ.Type.PRIVATE,
        sender = sender,
        msgId = msgId,
        payload = ByteArray(payloadSize) { (it * 31).toByte() },
    ).encode()

}
