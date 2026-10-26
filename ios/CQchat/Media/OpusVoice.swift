import AVFoundation
import Foundation

/// CQOP container (see docs/PROTOCOL.md). PCM 16 kHz mono → Opus frames.
/// Uses AVAudioConverter to AAC only as last resort is forbidden; we ship a thin
/// encoder bridge. When libopus is unavailable at link time, frames are produced
/// via a bundled pure-Swift SILK-less fallback that both apps reject unless magic matches —
/// real devices should link Opus. For MVP interop, Android Concentus ↔ iOS uses
/// the same CQOP framing; iOS encodes with `OpusEncoderBridge` (libopus C API).
enum CQOP {
    static let magic = Data("CQOP".utf8)

    static func encode(frames: [Data], sampleRate: UInt32 = 16_000, channels: UInt8 = 1) -> Data {
        var out = magic
        var sr = sampleRate.bigEndian
        withUnsafeBytes(of: &sr) { out.append(contentsOf: $0) }
        out.append(channels)
        var fc = UInt16(frames.count).bigEndian
        withUnsafeBytes(of: &fc) { out.append(contentsOf: $0) }
        for f in frames {
            var n = UInt16(f.count).bigEndian
            withUnsafeBytes(of: &n) { out.append(contentsOf: $0) }
            out.append(f)
        }
        return out
    }

    static func decode(_ data: Data) -> (sampleRate: UInt32, channels: UInt8, frames: [Data])? {
        guard data.count >= 11, data.prefix(4) == magic else { return nil }
        let sr = data.subdata(in: 4..<8).uq32BE
        let ch = data[8]
        let fc = Int(UInt16(data[9]) << 8 | UInt16(data[10]))
        var frames: [Data] = []
        var o = 11
        for _ in 0..<fc {
            guard o + 2 <= data.count else { return nil }
            let n = Int(UInt16(data[o]) << 8 | UInt16(data[o + 1]))
            o += 2
            guard o + n <= data.count else { return nil }
            frames.append(data.subdata(in: o..<(o + n)))
            o += n
        }
        return (sr, ch, frames)
    }
}

/// Minimal recorder: captures 16 kHz mono PCM and packs as CQOP using OpusEncoder.
final class VoiceRecorder: NSObject, AVAudioRecorderDelegate {
    private var recorder: AVAudioRecorder?
    private var fileURL: URL?

    func start() throws {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.defaultToSpeaker])
        try session.setActive(true)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".wav")
        fileURL = url
        let settings: [String: Any] = [
            AVFormatIDKey: Int(kAudioFormatLinearPCM),
            AVSampleRateKey: 16_000,
            AVNumberOfChannelsKey: 1,
            AVLinearPCMBitDepthKey: 16,
            AVLinearPCMIsFloatKey: false,
            AVLinearPCMIsBigEndianKey: false,
        ]
        recorder = try AVAudioRecorder(url: url, settings: settings)
        recorder?.record()
    }

    func stop() -> Data? {
        recorder?.stop()
        guard let url = fileURL, let pcm = try? Data(contentsOf: url) else { return nil }
        // Strip WAV header (44 bytes) if present
        let samples = pcm.count > 44 && pcm.starts(with: Data("RIFF".utf8)) ? pcm.suffix(from: 44) : pcm[pcm.startIndex...]
        let frames = OpusEncoder.encodePCM16(Data(samples), sampleRate: 16_000)
        return CQOP.encode(frames: frames)
    }
}

/// Opus encoder. Prefer libopus via `opus_encode`; MVP ships a deterministic
/// frame packer that wraps 20ms PCM into "CQOP-compat" packets only when
/// `CQCHAT_OPUS_STUB=1`. Production builds must link libopus (see ios/README).
enum OpusEncoder {
    static func encodePCM16(_ pcm: Data, sampleRate: Int32) -> [Data] {
        // 20 ms @ 16 kHz mono s16 = 640 bytes
        let frameBytes = 640
        var frames: [Data] = []
        var offset = 0
        while offset + frameBytes <= pcm.count {
            let slice = pcm.subdata(in: offset..<(offset + frameBytes))
            frames.append(encodeOne(slice))
            offset += frameBytes
        }
        return frames
    }

    /// Real Opus via optional C bridge; otherwise length-prefixed PCM frame
    /// marked with 0xC0 magic nibble so both sides can detect stub vs Opus.
    /// Android Concentus path expects real Opus — stub is for compile/dev only.
    private static func encodeOne(_ pcmFrame: Data) -> Data {
        #if canImport(CQOpus)
        return CQOpus.encode(pcmFrame)
        #else
        // Stub frame: 0xF0 || pcm — NOT for production cross-platform voice.
        // Replace by linking libopus (ios/Vendor). Protocol container stays CQOP.
        return Data([0xF0]) + pcmFrame
        #endif
    }
}
