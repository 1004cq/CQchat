import Foundation
import CoreBluetooth

enum CQ {
    static let version: UInt8 = 0x01
    static let bleMtuPayload = 512
    static let ttlDefault: UInt8 = 7
    static let tempIdRotateSecs: TimeInterval = 180
    static let dedupTtlSecs: TimeInterval = 300
    static let msgExpirySecs: TimeInterval = 600
    static let maxRetries = 5
    static let ackRetrySecs: TimeInterval = 2.5
    static let tcpPort: UInt16 = 37251
    static let mdnsType = "_cqchat._tcp."
    static let mediaBleMax = 102_400
    static let imageMaxEdge: CGFloat = 1280
    static let imageJpegQuality: CGFloat = 0.7
    static let nearbyNotifyCooldown: TimeInterval = 600

    static let serviceUUID = CBUUID(string: "C1C10001-C1C1-4000-8000-00000000C1C1")
    static let inboxUUID = CBUUID(string: "C1C10002-C1C1-4000-8000-00000000C1C1")

    enum PacketType: UInt8 {
        case discover = 0x01
        case broadcast = 0x02
        case handshake = 0x03
        case privateMsg = 0x04
        case ack = 0x05
        case sync = 0x06
        case mediaMeta = 0x07
        case fragment = 0x08
    }

    enum Flag {
        static let needsAck: UInt8 = 0x01
    }

    enum ContentType: UInt8 {
        case text = 0x01
        case image = 0x02
        case voice = 0x03
        case hello = 0x10
    }

    static let headerSize = 38
    static let qrPrefix = "cqchat:v1:"
}
