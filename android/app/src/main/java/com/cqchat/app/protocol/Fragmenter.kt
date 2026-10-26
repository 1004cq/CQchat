package com.cqchat.app.protocol

object Fragmenter {
    fun split(
        rawPacket: ByteArray,
        sender: ByteArray,
        msgId: ByteArray,
        ttl: Int,
        chunkSize: Int = CQ.BLE_MTU_PAYLOAD,
    ): List<ByteArray> {
        val total = maxOf(1, (rawPacket.size + chunkSize - 1) / chunkSize)
        return (0 until total).map { i ->
            val start = i * chunkSize
            val end = minOf(start + chunkSize, rawPacket.size)
            val piece = rawPacket.copyOfRange(start, end)
            val payload = FragmentPayload.encode(i, total, piece)
            CQPacket.make(
                type = CQ.Type.FRAGMENT,
                sender = sender,
                msgId = msgId,
                ttl = ttl,
                payload = payload,
            ).encode()
        }
    }
}

class FragmentReassembler {
    private data class Entry(var total: Int, val parts: MutableMap<Int, ByteArray>, var lastSeen: Long)

    private val pending = HashMap<String, Entry>()

    fun ingest(fragmentPacket: CQPacket): ByteArray? {
        val decoded = FragmentPayload.decode(fragmentPacket.payload) ?: return null
        val (index, total, data) = decoded
        val key = fragmentPacket.msgId.toHex()
        purge()
        val entry = pending.getOrPut(key) { Entry(total, HashMap(), System.currentTimeMillis()) }
        entry.total = total
        entry.parts[index] = data
        entry.lastSeen = System.currentTimeMillis()
        if (entry.parts.size == entry.total) {
            pending.remove(key)
            val out = ArrayList<Byte>()
            for (i in 0 until entry.total) {
                val part = entry.parts[i] ?: return null
                out.addAll(part.toList())
            }
            return out.toByteArray()
        }
        return null
    }

    private fun purge() {
        val cutoff = System.currentTimeMillis() - CQ.DEDUP_TTL_SECS * 1000
        pending.entries.removeAll { it.value.lastSeen < cutoff }
    }
}
