package com.cqchat.app.protocol

object Fragmenter {
    fun split(
        rawPacket: ByteArray,
        sender: ByteArray,
        msgId: ByteArray,
        ttl: Int,
        chunkSize: Int = CQ.BLE_MTU_PAYLOAD,
    ): List<ByteArray> {
        require(chunkSize in 1..0xffff - 4) { "invalid fragment chunk size" }
        require(sender.size == 16 && msgId.size == 16) { "invalid packet identifiers" }
        require(rawPacket.size <= CQ.MAX_REASSEMBLY_BYTES) { "packet is too large for BLE reassembly" }
        val original = CQPacket.decode(rawPacket) ?: throw IllegalArgumentException("invalid raw packet")
        require(original.sender.contentEquals(sender) && original.msgId.contentEquals(msgId)) {
            "fragment identifiers do not match raw packet"
        }
        val total = maxOf(1, (rawPacket.size + chunkSize - 1) / chunkSize)
        require(total <= CQ.MAX_FRAGMENT_COUNT && total <= 0xffff) { "too many fragments" }
        return (0 until total).map { index ->
            val start = index * chunkSize
            val end = minOf(start + chunkSize, rawPacket.size)
            val payload = FragmentPayload.encode(index, total, rawPacket.copyOfRange(start, end))
            CQPacket.make(
                type = CQ.Type.FRAGMENT,
                sender = sender.copyOf(),
                msgId = msgId.copyOf(),
                ttl = ttl,
                destination = original.destination.copyOf(),
                nextHop = original.nextHop.copyOf(),
                payload = payload,
            ).encode()
        }
    }
}

class FragmentReassembler {
    private data class Entry(
        val total: Int,
        val parts: MutableMap<Int, ByteArray>,
        var bytes: Int,
        var lastSeen: Long,
    )

    private val lock = Any()
    private val pending = HashMap<String, Entry>()

    fun ingest(fragmentPacket: CQPacket): ByteArray? = synchronized(lock) {
        purgeLocked()
        val decoded = FragmentPayload.decode(fragmentPacket.payload) ?: return@synchronized null
        val (index, total, data) = decoded
        if (total !in 1..CQ.MAX_FRAGMENT_COUNT || index !in 0 until total) return@synchronized null
        if (data.isEmpty() || data.size > CQ.MAX_REASSEMBLY_BYTES) return@synchronized null

        val key = fragmentPacket.sender.toHex() + ":" + fragmentPacket.msgId.toHex()
        var entry = pending[key]
        if (entry == null) {
            if (pending.size >= CQ.MAX_PENDING_REASSEMBLIES) evictOldestLocked()
            entry = Entry(total, HashMap(), 0, System.currentTimeMillis())
            pending[key] = entry
        } else if (entry.total != total) {
            return@synchronized null
        }

        if (entry.parts[index] == null) {
            if (entry.bytes > CQ.MAX_REASSEMBLY_BYTES - data.size) {
                pending.remove(key)
                return@synchronized null
            }
            entry.parts[index] = data.copyOf()
            entry.bytes += data.size
        }
        entry.lastSeen = System.currentTimeMillis()
        if (entry.parts.size != entry.total) return@synchronized null

        val output = ByteArray(entry.bytes)
        var offset = 0
        for (partIndex in 0 until entry.total) {
            val part = entry.parts[partIndex] ?: return@synchronized null
            part.copyInto(output, offset)
            offset += part.size
        }
        pending.remove(key)
        output
    }

    fun clear() = synchronized(lock) { pending.clear() }

    private fun purgeLocked() {
        val cutoff = System.currentTimeMillis() - CQ.DEDUP_TTL_SECS * 1000
        pending.entries.removeAll { it.value.lastSeen < cutoff }
    }

    private fun evictOldestLocked() {
        val oldest = pending.entries.minByOrNull { it.value.lastSeen } ?: return
        pending.remove(oldest.key)
    }
}

/** Pure BLE wire chunking used by BleMeshService and directly unit-testable. */
object BleMeshPacketCodec {
    fun split(packet: ByteArray, maxPayload: Int): List<ByteArray> {
        require(maxPayload > 0) { "invalid ATT payload size" }
        if (CQPacket.decode(packet) == null) return emptyList()
        if (packet.size <= maxPayload) return listOf(packet.copyOf())
        return try {
            if (maxPayload <= BleMiniFragmenter.HEADER_SIZE) {
                BleMiniFragmenter.split(packet, maxPayload)
            } else {
                val decoded = CQPacket.decode(packet) ?: return emptyList()
                if (maxPayload < CQ.HEADER_SIZE + 4) {
                    BleMiniFragmenter.split(packet, maxPayload)
                } else {
                    val chunkSize = maxPayload - CQ.HEADER_SIZE - 4
                    Fragmenter.split(packet, decoded.sender, decoded.msgId, decoded.ttl, chunkSize)
                        .filter { it.size <= maxPayload }
                }
            }
        } catch (_: IllegalArgumentException) {
            emptyList()
        }
    }
}

/**
 * Compact BLE envelope used when ATT payload cannot carry the 38-byte CQPacket
 * header. It is removed before CQPacket decoding:
 *
 *   magic(2) | version(1) | index(2) | total(2) | token(8) | data(n)
 *
 * The token is the first 8 bytes of SHA-256(sender||msgId). The complete
 * CQPacket remains the source of truth for authentication and deduplication.
 */
object BleMiniFragmenter {
    const val HEADER_SIZE = 15
    private const val MAGIC_0: Int = 0x43 // C
    private const val MAGIC_1: Int = 0x51 // Q
    private const val VERSION: Int = 1
    private const val MAX_TOTAL = 0xffff
    private const val TOKEN_SIZE = 8

    fun split(rawPacket: ByteArray, maxPayload: Int): List<ByteArray> {
        require(maxPayload > HEADER_SIZE) { "ATT payload is too small for BLE mini fragments" }
        require(rawPacket.size <= CQ.MAX_REASSEMBLY_BYTES) { "packet is too large for BLE" }
        require(rawPacket.isNotEmpty())
        val decoded = CQPacket.decode(rawPacket) ?: error("invalid CQPacket")
        val token = NoiseXX.sha256(decoded.sender + decoded.msgId).copyOf(TOKEN_SIZE)
        val chunkSize = maxPayload - HEADER_SIZE
        val total = (rawPacket.size + chunkSize - 1) / chunkSize
        require(total in 1..MAX_TOTAL) { "packet requires too many BLE fragments" }
        return (0 until total).map { index ->
            val start = index * chunkSize
            val end = minOf(start + chunkSize, rawPacket.size)
            encode(index, total, token, rawPacket.copyOfRange(start, end))
        }
    }

    fun encode(index: Int, total: Int, token: ByteArray, data: ByteArray): ByteArray {
        require(index in 0 until total && total in 1..MAX_TOTAL)
        require(token.size == TOKEN_SIZE)
        return ByteArray(HEADER_SIZE + data.size).also { out ->
            out[0] = MAGIC_0.toByte()
            out[1] = MAGIC_1.toByte()
            out[2] = VERSION.toByte()
            out[3] = (index ushr 8).toByte()
            out[4] = index.toByte()
            out[5] = (total ushr 8).toByte()
            out[6] = total.toByte()
            token.copyInto(out, 7)
            data.copyInto(out, HEADER_SIZE)
        }
    }

    fun decode(data: ByteArray): Decoded? {
        if (data.size < HEADER_SIZE ||
            (data[0].toInt() and 0xff) != MAGIC_0 ||
            (data[1].toInt() and 0xff) != MAGIC_1
        ) return null
        if ((data[2].toInt() and 0xff) != VERSION) return null
        val index = ((data[3].toInt() and 0xff) shl 8) or (data[4].toInt() and 0xff)
        val total = ((data[5].toInt() and 0xff) shl 8) or (data[6].toInt() and 0xff)
        if (total == 0 || index >= total) return null
        return Decoded(index, total, data.copyOfRange(7, 15), data.copyOfRange(HEADER_SIZE, data.size))
    }

    data class Decoded(val index: Int, val total: Int, val token: ByteArray, val data: ByteArray)
}

class BleMiniReassembler {
    private data class Entry(
        val total: Int,
        val parts: MutableMap<Int, ByteArray>,
        var bytes: Int,
        var lastSeen: Long,
    )

    private val lock = Any()
    private val pending = HashMap<String, Entry>()

    fun ingest(fragment: BleMiniFragmenter.Decoded): ByteArray? = synchronized(lock) {
        purgeLocked()
        val key = fragment.token.toHex()
        var entry = pending[key]
        if (entry == null) {
            if (pending.size >= CQ.MAX_PENDING_REASSEMBLIES) evictOldestLocked()
            entry = Entry(fragment.total, HashMap(), 0, System.currentTimeMillis())
            pending[key] = entry
        } else if (entry.total != fragment.total) {
            return@synchronized null
        }
        if (fragment.data.isEmpty()) return@synchronized null
        if (entry.parts[fragment.index] == null) {
            if (entry.bytes > CQ.MAX_REASSEMBLY_BYTES - fragment.data.size) {
                pending.remove(key)
                return@synchronized null
            }
            entry.parts[fragment.index] = fragment.data.copyOf()
            entry.bytes += fragment.data.size
        }
        entry.lastSeen = System.currentTimeMillis()
        if (entry.parts.size != entry.total) return@synchronized null

        val output = ByteArray(entry.bytes)
        var offset = 0
        for (i in 0 until entry.total) {
            val part = entry.parts[i] ?: return@synchronized null
            part.copyInto(output, offset)
            offset += part.size
        }
        pending.remove(key)
        output
    }

    fun clear() = synchronized(lock) { pending.clear() }

    private fun purgeLocked() {
        val cutoff = System.currentTimeMillis() - CQ.DEDUP_TTL_SECS * 1000
        pending.entries.removeAll { it.value.lastSeen < cutoff }
    }

    private fun evictOldestLocked() {
        val oldest = pending.entries.minByOrNull { it.value.lastSeen } ?: return
        pending.remove(oldest.key)
    }
}
