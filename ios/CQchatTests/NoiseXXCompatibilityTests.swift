import XCTest
@testable import CQchat

/// Cross-platform contract shared with
/// android/app/src/test/.../NoiseCrossPlatformCompatibilityTest.kt.
/// Add this file to the CQchatTests target in Xcode.
final class NoiseXXCompatibilityTests: XCTestCase {
    func testAllZeroX25519PublicKeyIsRejectedBeforeHKDF() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let zeroPublicKey = Data(repeating: 0, count: 32)

        XCTAssertThrowsError(
            try NoiseXX.checkedSharedSecret(
                privateKey: privateKey,
                publicKeyRawRepresentation: zeroPublicKey
            )
        ) { error in
            guard case NoiseError.invalidKey = error else {
                return XCTFail("expected NoiseError.invalidKey, got \(error)")
            }
        }
    }

    func testIdentityBindingMessageMatchesSharedVector() {
        let x25519 = Data((0..<32).map { UInt8($0) })
        let ed25519 = Data((32..<64).map { UInt8($0) })
        let expected = Data.fromHex(
            "435163686174206964656e746974792062696e64696e6720763101" +
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        )!
        XCTAssertEqual(
            IdentityKeys.identityBindingMessage(x25519Public: x25519, ed25519Public: ed25519),
            expected
        )
    }

    func testIdentityBindingSignatureRejectsAChangedX25519Key() throws {
        let x25519 = Curve25519.KeyAgreement.PrivateKey()
        let ed25519 = Curve25519.Signing.PrivateKey()
        let signature = try IdentityKeys.signIdentityBinding(
            x25519Private: x25519,
            ed25519Private: ed25519
        )
        let xPublic = x25519.publicKey.rawRepresentation
        let edPublic = ed25519.publicKey.rawRepresentation
        XCTAssertTrue(IdentityKeys.verifyIdentityBinding(
            ed25519Public: edPublic,
            x25519Public: xPublic,
            signature: signature
        ))

        var tampered = xPublic
        tampered[0] ^= 1
        XCTAssertFalse(IdentityKeys.verifyIdentityBinding(
            ed25519Public: edPublic,
            x25519Public: tampered,
            signature: signature
        ))
    }

    func testThreeMessageNoiseXXHandshakeMatchesAndroidPattern() throws {
        let initiator = NoiseXX(
            role: .initiator,
            staticKey: Curve25519.KeyAgreement.PrivateKey()
        )
        let responder = NoiseXX(
            role: .responder,
            staticKey: Curve25519.KeyAgreement.PrivateKey()
        )

        let message1 = try initiator.initiatorWrite1(payload: Data("m1".utf8))
        XCTAssertEqual(try responder.responderRead1(message1), Data("m1".utf8))
        let message2 = try responder.responderWrite2(payload: Data("m2".utf8))
        XCTAssertEqual(try initiator.initiatorRead2(message2), Data("m2".utf8))
        let message3 = try initiator.initiatorWrite3(payload: Data("m3".utf8))
        XCTAssertEqual(try responder.responderRead3(message3), Data("m3".utf8))

        XCTAssertTrue(initiator.completed)
        XCTAssertTrue(responder.completed)
        let fromInitiator = try initiator.encrypt(Data("android-to-ios".utf8))
        XCTAssertEqual(try responder.decrypt(fromInitiator), Data("android-to-ios".utf8))
        let fromResponder = try responder.encrypt(Data("ios-to-android".utf8))
        XCTAssertEqual(try initiator.decrypt(fromResponder), Data("ios-to-android".utf8))
    }

    func testTransportCiphertextReplayIsRejected() throws {
        let (initiator, responder) = try completedSession()
        let ciphertext = try initiator.encrypt(Data("once-only".utf8))

        XCTAssertEqual(try responder.decrypt(ciphertext), Data("once-only".utf8))
        XCTAssertThrowsError(try responder.decrypt(ciphertext))
    }

    func testFailedAeadDoesNotConsumeReceiveNonce() throws {
        let key = SymmetricKey(data: Data(repeating: 0x42, count: 32))
        let sender = CipherState(key: key)
        let receiver = CipherState(key: key)
        let plaintext = Data("must-survive-an-invalid-packet".utf8)
        let valid = try sender.encrypt(plaintext: plaintext, ad: Data("header".utf8))

        var tampered = valid
        tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(
            try receiver.decrypt(ciphertext: tampered, ad: Data("header".utf8))
        )

        XCTAssertEqual(
            try receiver.decrypt(ciphertext: valid, ad: Data("header".utf8)),
            plaintext
        )
    }

    func testTamperedRoutingAdIsRejectedWithoutAdvancingReceiveNonce() throws {
        let (initiator, responder) = try completedSession()
        let envelope = CQPacket.make(
            type: .privateMsg,
            sender: Data(repeating: 1, count: 16),
            destination: Data(repeating: 2, count: 16),
            payload: Data()
        )
        let valid = try initiator.encrypt(
            Data("ad-bound".utf8), associatedData: envelope.associatedData()
        )
        var tampered = envelope
        tampered.destination = Data(repeating: 9, count: 16)

        XCTAssertThrowsError(
            try responder.decrypt(valid, associatedData: tampered.associatedData())
        )
        XCTAssertEqual(
            try responder.decrypt(valid, associatedData: envelope.associatedData()),
            Data("ad-bound".utf8)
        )
    }

    func testHandshakeStep1ReplayCannotAdvanceResponderTwice() throws {
        let initiator = NoiseXX(role: .initiator, staticKey: .init())
        let responder = NoiseXX(role: .responder, staticKey: .init())
        let message1 = try initiator.initiatorWrite1()

        _ = try responder.responderRead1(message1)
        XCTAssertThrowsError(try responder.responderRead1(message1))
    }

    func testHandshakeStep2AndStep3ReplaysAreRejected() throws {
        let initiator = NoiseXX(role: .initiator, staticKey: .init())
        let responder = NoiseXX(role: .responder, staticKey: .init())
        _ = try responder.responderRead1(initiator.initiatorWrite1())
        let message2 = try responder.responderWrite2()
        _ = try initiator.initiatorRead2(message2)
        XCTAssertThrowsError(try initiator.initiatorRead2(message2))

        let message3 = try initiator.initiatorWrite3()
        _ = try responder.responderRead3(message3)
        XCTAssertThrowsError(try responder.responderRead3(message3))
    }

    func testTamperedHandshakeStep2IsRejectedBeforeCompletion() throws {
        let initiator = NoiseXX(role: .initiator, staticKey: .init())
        let responder = NoiseXX(role: .responder, staticKey: .init())
        _ = try responder.responderRead1(initiator.initiatorWrite1())
        var message2 = try responder.responderWrite2()
        message2[message2.count - 1] ^= 1

        XCTAssertThrowsError(try initiator.initiatorRead2(message2))
        XCTAssertFalse(initiator.completed)
    }

    func testTamperedHandshakeStep3IsRejectedBeforeCompletion() throws {
        let initiator = NoiseXX(role: .initiator, staticKey: .init())
        let responder = NoiseXX(role: .responder, staticKey: .init())
        _ = try responder.responderRead1(initiator.initiatorWrite1())
        _ = try initiator.initiatorRead2(responder.responderWrite2())
        var message3 = try initiator.initiatorWrite3(payload: Data("binding".utf8))
        message3[message3.count - 1] ^= 1

        XCTAssertThrowsError(try responder.responderRead3(message3))
        XCTAssertFalse(responder.completed)
    }

    func testPacketMessageIdReplayIsDeduplicated() {
        let cache = DedupCache()
        let msgId = Data((0..<16).map { UInt8($0 + 9) })
        XCTAssertFalse(cache.seen(msgId))
        XCTAssertTrue(cache.seen(msgId))
    }

    private func completedSession() throws -> (NoiseXX, NoiseXX) {
        let initiator = NoiseXX(role: .initiator, staticKey: .init())
        let responder = NoiseXX(role: .responder, staticKey: .init())
        _ = try responder.responderRead1(initiator.initiatorWrite1())
        _ = try initiator.initiatorRead2(responder.responderWrite2())
        _ = try responder.responderRead3(initiator.initiatorWrite3())
        return (initiator, responder)
    }
}
