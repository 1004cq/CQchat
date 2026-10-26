package com.cqchat.app.chat

import com.cqchat.app.protocol.CQ
import java.util.concurrent.ConcurrentHashMap

/** Wire-level resend tracker (ACK / expiry / retries). */
class PendingOutbound {
    data class Entry(
        val msgId: ByteArray,
        val wire: ByteArray,
        val destKey: ByteArray,
        var tries: Int,
        val createdAt: Long,
        val kind: Kind,
    ) {
        enum class Kind { TEXT, MEDIA }
    }

    private val map = ConcurrentHashMap<String, Entry>()

    fun put(e: Entry) {
        map[e.msgId.toHexSafe()] = e
    }

    fun remove(msgId: ByteArray): Entry? = map.remove(msgId.toHexSafe())

    fun get(msgId: ByteArray): Entry? = map[msgId.toHexSafe()]

    fun dueForRetry(now: Long = System.currentTimeMillis()): List<Entry> {
        val out = ArrayList<Entry>()
        for (e in map.values) {
            if (now - e.createdAt > CQ.MSG_EXPIRY_SECS * 1000L) continue
            if (e.tries >= CQ.MAX_RETRIES) continue
            out.add(e)
        }
        return out
    }

    fun expired(now: Long = System.currentTimeMillis()): List<Entry> {
        return map.values.filter {
            now - it.createdAt > CQ.MSG_EXPIRY_SECS * 1000L || it.tries >= CQ.MAX_RETRIES
        }
    }

    fun allForDest(dest: ByteArray): List<Entry> =
        map.values.filter { it.destKey.contentEquals(dest) }

    private fun ByteArray.toHexSafe(): String = joinToString("") { "%02x".format(it) }
}
