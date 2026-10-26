package com.cqchat.app.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

data class CQPacket(
    val version: Int,
    val type: Int,
    val flags: Int,
    val sender: ByteArray,
    val msgId: ByteArray,
    val destination: ByteArray,
    val nextHop: ByteArray,
    val ttl: Int,
    val payload: ByteArray,
) {
    /** Authenticates immutable envelope metadata; TTL is hop-by-hop and excluded. */
    fun associatedData(): ByteArray =
        "CQchat packet AD v2".toByteArray(Charsets.UTF_8) + byteArrayOf(
            version.toByte(), type.toByte(), flags.toByte(),
        ) + sender + msgId + destination + nextHop

    fun encode(): ByteArray {
        require(sender.size == 16 && msgId.size == 16)
        require(destination.size == 16 && nextHop.size == 16)
        require(payload.size <= 0xFFFF)
        val buf = ByteBuffer.allocate(CQ.HEADER_SIZE + payload.size).order(ByteOrder.BIG_ENDIAN)
        buf.put(version.toByte())
        buf.put(type.toByte())
        buf.put(flags.toByte())
        buf.put(sender)
        buf.put(msgId)
        buf.put(destination)
        buf.put(nextHop)
        buf.put(ttl.toByte())
        buf.putShort(payload.size.toShort())
        buf.put(payload)
        return buf.array()
    }

    companion object {
        fun decode(data: ByteArray): CQPacket? {
            if (data.size < CQ.HEADER_SIZE) return null
            val buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
            val version = buf.get().toInt() and 0xff
            val type = buf.get().toInt() and 0xff
            val flags = buf.get().toInt() and 0xff
            val sender = ByteArray(16).also { buf.get(it) }
            val msgId = ByteArray(16).also { buf.get(it) }
            val destination = ByteArray(16).also { buf.get(it) }
            val nextHop = ByteArray(16).also { buf.get(it) }
            val ttl = buf.get().toInt() and 0xff
            val plen = buf.short.toInt() and 0xffff
            if (data.size != CQ.HEADER_SIZE + plen) return null
            val payload = ByteArray(plen).also { buf.get(it) }
            return CQPacket(version, type, flags, sender, msgId, destination, nextHop, ttl, payload)
        }

        fun make(
            type: Int,
            sender: ByteArray,
            msgId: ByteArray = random16(),
            ttl: Int = CQ.TTL_DEFAULT,
            flags: Int = 0,
            destination: ByteArray = broadcastAddress(),
            nextHop: ByteArray = broadcastAddress(),
            payload: ByteArray,
        ): CQPacket = CQPacket(CQ.VERSION, type, flags, sender, msgId, destination, nextHop, ttl, payload)

        fun random16(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }

        fun broadcastAddress(): ByteArray = ByteArray(16)

        fun isBroadcastAddress(address: ByteArray): Boolean =
            address.size == 16 && address.all { it == 0.toByte() }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CQPacket) return false
        return version == other.version && type == other.type && flags == other.flags &&
            sender.contentEquals(other.sender) && msgId.contentEquals(other.msgId) &&
            destination.contentEquals(other.destination) && nextHop.contentEquals(other.nextHop) &&
            ttl == other.ttl && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int = msgId.contentHashCode()
}

object BroadcastPayload {
    fun encode(nickname: String, text: String, edPk: ByteArray, sig: ByteArray): ByteArray {
        val nb = nickname.toByteArray(Charsets.UTF_8)
        val tb = text.toByteArray(Charsets.UTF_8)
        val buf = ByteBuffer.allocate(1 + nb.size + 2 + tb.size + 32 + 64).order(ByteOrder.BIG_ENDIAN)
        buf.put(nb.size.toByte())
        buf.put(nb)
        buf.putShort(tb.size.toShort())
        buf.put(tb)
        buf.put(edPk)
        buf.put(sig)
        return buf.array()
    }

    fun decode(data: ByteArray): Quad? {
        if (data.isEmpty()) return null
        var o = 0
        val nlen = data[o].toInt() and 0xff; o++
        if (data.size < o + nlen + 2) return null
        val nick = data.copyOfRange(o, o + nlen).toString(Charsets.UTF_8); o += nlen
        val tlen = ((data[o].toInt() and 0xff) shl 8) or (data[o + 1].toInt() and 0xff); o += 2
        if (data.size < o + tlen + 32 + 64) return null
        val text = data.copyOfRange(o, o + tlen).toString(Charsets.UTF_8); o += tlen
        val pk = data.copyOfRange(o, o + 32); o += 32
        val sig = data.copyOfRange(o, o + 64)
        return Quad(nick, text, pk, sig)
    }

    fun signMessage(msgId: ByteArray, nickname: String, text: String): ByteArray =
        msgId + nickname.toByteArray(Charsets.UTF_8) + text.toByteArray(Charsets.UTF_8)

    data class Quad(val nickname: String, val text: String, val pk: ByteArray, val sig: ByteArray)
}

object HandshakePayload {
    fun encode(step: Int, body: ByteArray, pattern: Int = 1): ByteArray =
        byteArrayOf(pattern.toByte(), step.toByte()) + body

    fun decode(data: ByteArray): Triple<Int, Int, ByteArray>? {
        if (data.size < 2) return null
        return Triple(data[0].toInt() and 0xff, data[1].toInt() and 0xff, data.copyOfRange(2, data.size))
    }
}

object AckPayload {
    fun encode(ackMsgId: ByteArray): ByteArray {
        require(ackMsgId.size == 16)
        return ackMsgId
    }

    fun decode(data: ByteArray): ByteArray? = data.takeIf { it.size == 16 }
}

object FragmentPayload {
    fun encode(index: Int, total: Int, data: ByteArray): ByteArray {
        require(index in 0 until total && total in 1..CQ.MAX_FRAGMENT_COUNT)
        val buf = ByteBuffer.allocate(4 + data.size).order(ByteOrder.BIG_ENDIAN)
        buf.putShort(index.toShort())
        buf.putShort(total.toShort())
        buf.put(data)
        return buf.array()
    }

    fun decode(data: ByteArray): Triple<Int, Int, ByteArray>? {
        if (data.size < 4) return null
        val index = ((data[0].toInt() and 0xff) shl 8) or (data[1].toInt() and 0xff)
        val total = ((data[2].toInt() and 0xff) shl 8) or (data[3].toInt() and 0xff)
        if (total !in 1..CQ.MAX_FRAGMENT_COUNT || index !in 0 until total) return null
        return Triple(index, total, data.copyOfRange(4, data.size))
    }
}

object PrivatePlaintext {
    fun encode(contentType: Int, body: ByteArray): ByteArray =
        byteArrayOf(contentType.toByte()) + body

    fun decode(data: ByteArray): Pair<Int, ByteArray>? {
        if (data.isEmpty()) return null
        return (data[0].toInt() and 0xff) to data.copyOfRange(1, data.size)
    }
}

object MediaContainer {
    fun encode(thumb: ByteArray, data: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(8 + thumb.size + data.size).order(ByteOrder.BIG_ENDIAN)
        buf.putInt(thumb.size)
        buf.put(thumb)
        buf.putInt(data.size)
        buf.put(data)
        return buf.array()
    }

    fun decode(data: ByteArray): Pair<ByteArray, ByteArray>? {
        if (data.size < 8) return null
        val buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val tl = buf.int
        if (tl < 0 || tl > CQ.MAX_REASSEMBLY_BYTES || data.size < 4 + tl + 4) return null
        val thumb = ByteArray(tl).also { buf.get(it) }
        val dl = buf.int
        if (dl < 0 || dl > CQ.MAX_REASSEMBLY_BYTES || data.size != 4 + tl + 4 + dl) return null
        val body = ByteArray(dl).also { buf.get(it) }
        return thumb to body
    }
}

object TcpFrame {
    fun encode(packet: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(4 + packet.size).order(ByteOrder.BIG_ENDIAN)
        buf.putInt(packet.size)
        buf.put(packet)
        return buf.array()
    }
}

object CQOP {
    private val MAGIC = "CQOP".toByteArray(Charsets.US_ASCII)

    fun encode(frames: List<ByteArray>, sampleRate: Int = 16000, channels: Int = 1): ByteArray {
        val size = 11 + frames.sumOf { 2 + it.size }
        val buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN)
        buf.put(MAGIC)
        buf.putInt(sampleRate)
        buf.put(channels.toByte())
        buf.putShort(frames.size.toShort())
        for (f in frames) {
            buf.putShort(f.size.toShort())
            buf.put(f)
        }
        return buf.array()
    }

    fun decode(data: ByteArray): Triple<Int, Int, List<ByteArray>>? {
        if (data.size < 11) return null
        if (!data.copyOfRange(0, 4).contentEquals(MAGIC)) return null
        val buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        buf.position(4)
        val sr = buf.int
        val ch = buf.get().toInt() and 0xff
        val fc = buf.short.toInt() and 0xffff
        val frames = ArrayList<ByteArray>(fc)
        repeat(fc) {
            val n = buf.short.toInt() and 0xffff
            val fr = ByteArray(n).also { buf.get(it) }
            frames.add(fr)
        }
        return Triple(sr, ch, frames)
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToBytes(): ByteArray? {
    val clean = replace(" ", "")
    if (clean.length % 2 != 0) return null
    return ByteArray(clean.length / 2) { i ->
        clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}
