package com.cqchat.app.protocol

import java.util.UUID

object CQ {
    const val VERSION: Int = 0x01
    const val BLE_MTU_PAYLOAD: Int = 512
    const val TTL_DEFAULT: Int = 7
    const val TEMP_ID_ROTATE_SECS: Long = 180
    const val DEDUP_TTL_SECS: Long = 300
    const val MSG_EXPIRY_SECS: Long = 600
    const val MAX_RETRIES: Int = 5
    const val ACK_RETRY_MS: Long = 2_500
    const val TCP_PORT: Int = 37251
    const val MDNS_TYPE: String = "_cqchat._tcp."
    const val MEDIA_BLE_MAX: Int = 102_400
    const val IMAGE_MAX_EDGE: Int = 1280
    const val IMAGE_JPEG_QUALITY: Int = 70
    const val NEARBY_NOTIFY_COOLDOWN_MS: Long = 600_000
    const val FAVORITE_NOTIFY_COOLDOWN_MS: Long = 600_000
    /** Peer marked unreachable if no BLE discovery / RX for this long. */
    const val PEER_UNREACHABLE_MS: Long = 60_000
    const val HEADER_SIZE: Int = 38
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
