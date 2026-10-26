package com.cqchat.app.protocol

import java.util.UUID

object CQ {
    const val VERSION: Int = 0x02
    const val BLE_MTU_PAYLOAD: Int = 512
    const val TTL_DEFAULT: Int = 7
    const val TEMP_ID_ROTATE_SECS: Long = 180
    const val DEDUP_TTL_SECS: Long = 300
    const val MAX_FRAGMENT_COUNT: Int = 4_096
    const val MAX_REASSEMBLY_BYTES: Int = 131_072
    const val MAX_PENDING_REASSEMBLIES: Int = 128
    const val TCP_PORT: Int = 37251
    const val MDNS_TYPE: String = "_cqchat._tcp."
    // CQPacket payload is encoded as an unsigned 16-bit length. Keep the
    // transport limit close to the actual protocol limit to avoid large
    // attacker-controlled allocations in the TCP reader.
    const val TCP_MAX_FRAME_BYTES: Int = 70 + 65_535
    const val TCP_MAX_WORKERS: Int = 8
    const val TCP_WORK_QUEUE: Int = 64
    const val TCP_CONNECT_TIMEOUT_MS: Int = 5_000
    const val TCP_READ_TIMEOUT_MS: Int = 15_000
    const val TCP_HEARTBEAT_TIMEOUT_MS: Long = 45_000
    const val TCP_PING_FRAME: Int = 0
    const val TCP_PONG_FRAME: Int = -1
    const val TCP_MAX_RECONNECT_ATTEMPTS: Int = 5
    const val TCP_RECONNECT_BASE_DELAY_MS: Long = 1_000
    const val TCP_RECONNECT_MAX_DELAY_MS: Long = 30_000
    const val MEDIA_BLE_MAX: Int = 102_400
    const val IMAGE_MAX_EDGE: Int = 1280
    const val IMAGE_JPEG_QUALITY: Int = 70
    const val NEARBY_NOTIFY_COOLDOWN_MS: Long = 600_000
    // version/type/flags + sender/msgId/destination/nextHop + ttl/length
    const val HEADER_SIZE: Int = 70
    const val QR_PREFIX: String = "cqchat:v1:"

    val SERVICE_UUID: UUID = UUID.fromString("c1c10001-c1c1-4000-8000-00000000c1c1")
    val INBOX_UUID: UUID = UUID.fromString("c1c10002-c1c1-4000-8000-00000000c1c1")

    object Type {
        const val DISCOVER: Int = 0x01
        const val BROADCAST: Int = 0x02
        const val HANDSHAKE: Int = 0x03
        const val PRIVATE: Int = 0x04
        const val ACK: Int = 0x05
        const val SYNC: Int = 0x06
        const val MEDIA_META: Int = 0x07
        const val FRAGMENT: Int = 0x08
    }

    object Flag {
        const val NEEDS_ACK: Int = 0x01
    }

    object Content {
        const val TEXT: Int = 0x01
        const val IMAGE: Int = 0x02
        const val VOICE: Int = 0x03
        const val HELLO: Int = 0x10
    }
}
