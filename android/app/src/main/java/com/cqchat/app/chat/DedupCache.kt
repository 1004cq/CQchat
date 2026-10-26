package com.cqchat.app.chat

import com.cqchat.app.protocol.CQ
import com.cqchat.app.protocol.toHex

class DedupCache {
    private val map = HashMap<String, Long>()

    @Synchronized
    fun seen(msgId: ByteArray): Boolean {
        purge()
        val key = msgId.toHex()
        if (map.containsKey(key)) return true
        map[key] = System.currentTimeMillis()
        return false
    }

    @Synchronized
    fun clear() {
        map.clear()
    }

    @Synchronized
    private fun purge() {
        val cutoff = System.currentTimeMillis() - CQ.DEDUP_TTL_SECS * 1000
        map.entries.removeAll { it.value < cutoff }
    }
}
