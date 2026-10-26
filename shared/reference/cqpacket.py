#!/usr/bin/env python3
"""CQchat v1 packet reference encoder/decoder. Big-endian. Matches docs/protocol-v0.1.md."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
from pathlib import Path

VERSION = 0x01

TYPE_DISCOVER = 0x01
TYPE_BROADCAST = 0x02
TYPE_HANDSHAKE = 0x03
TYPE_PRIVATE = 0x04
TYPE_ACK = 0x05
TYPE_SYNC = 0x06
TYPE_MEDIA_META = 0x07
TYPE_FRAGMENT = 0x08

FLAG_NEEDS_ACK = 0x01

HEADER_SIZE = 38


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    if not salt:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def fingerprint(ed25519_public: bytes) -> bytes:
    """Identity fingerprint = SHA256(ed25519_public)[0:16] (not X25519)."""
    return hashlib.sha256(ed25519_public).digest()[:16]


def encode_header(
    typ: int,
    sender: bytes,
    msg_id: bytes,
    ttl: int,
    payload: bytes,
    flags: int = 0,
    version: int = VERSION,
) -> bytes:
    assert len(sender) == 16
    assert len(msg_id) == 16
    assert 0 <= ttl <= 255
    assert len(payload) <= 0xFFFF
    return struct.pack(
        "!BBB16s16sBH",
        version,
        typ,
        flags,
        sender,
        msg_id,
        ttl,
        len(payload),
    ) + payload


def decode_header(data: bytes) -> dict:
    if len(data) < HEADER_SIZE:
        raise ValueError("short packet")
    version, typ, flags, sender, msg_id, ttl, plen = struct.unpack(
        "!BBB16s16sBH", data[:HEADER_SIZE]
    )
    if len(data) < HEADER_SIZE + plen:
        raise ValueError("truncated payload")
    return {
        "version": version,
        "type": typ,
        "flags": flags,
        "sender": sender,
        "msg_id": msg_id,
        "ttl": ttl,
        "payload": data[HEADER_SIZE : HEADER_SIZE + plen],
    }


def encode_broadcast_payload(
    nickname: str, text: str, ed25519_pk: bytes, sig: bytes
) -> bytes:
    nb = nickname.encode("utf-8")
    tb = text.encode("utf-8")
    assert len(ed25519_pk) == 32 and len(sig) == 64
    return bytes([len(nb)]) + nb + struct.pack("!H", len(tb)) + tb + ed25519_pk + sig


def encode_ack_payload(ack_msg_id: bytes) -> bytes:
    assert len(ack_msg_id) == 16
    return ack_msg_id


def encode_handshake_payload(step: int, body: bytes, pattern: int = 1) -> bytes:
    return bytes([pattern, step]) + body


def encode_fragment_payload(index: int, total: int, data: bytes) -> bytes:
    return struct.pack("!HH", index, total) + data


def fragment_packet(raw: bytes, msg_id: bytes, sender: bytes, ttl: int, chunk: int) -> list[bytes]:
    """Split a full encoded packet into FRAGMENT packets sharing msg_id."""
    total = (len(raw) + chunk - 1) // chunk
    out = []
    for i in range(total):
        piece = raw[i * chunk : (i + 1) * chunk]
        payload = encode_fragment_payload(i, total, piece)
        out.append(
            encode_header(TYPE_FRAGMENT, sender, msg_id, ttl, payload)
        )
    return out


def reassemble_fragments(payloads: list[bytes]) -> bytes:
    parts = []
    total = None
    for p in payloads:
        index, tot = struct.unpack("!HH", p[:4])
        if total is None:
            total = tot
        assert tot == total
        parts.append((index, p[4:]))
    parts.sort(key=lambda x: x[0])
    assert [i for i, _ in parts] == list(range(total))
    return b"".join(d for _, d in parts)


def encode_private_plaintext(content_type: int, body: bytes) -> bytes:
    return bytes([content_type]) + body


def encode_media_container(thumb: bytes, data: bytes) -> bytes:
    return struct.pack("!I", len(thumb)) + thumb + struct.pack("!I", len(data)) + data


def encode_cqop(frames: list[bytes], sample_rate: int = 16000, channels: int = 1) -> bytes:
    out = b"CQOP" + struct.pack("!IBH", sample_rate, channels, len(frames))
    for fr in frames:
        out += struct.pack("!H", len(fr)) + fr
    return out


def tcp_frame(packet: bytes) -> bytes:
    return struct.pack("!I", len(packet)) + packet


def main() -> None:
    # Deterministic fixtures (not real crypto keys for Noise; packing only)
    sender = bytes(range(16))
    msg_id = bytes(range(16, 32))
    ed_pk = bytes([0x11] * 32)
    sig = bytes([0x22] * 64)

    vectors = {}

    empty = encode_header(TYPE_DISCOVER, sender, msg_id, 7, b"")
    vectors["discover_empty"] = {
        "hex": empty.hex(),
        "len": len(empty),
    }

    bcast_payload = encode_broadcast_payload("alice", "hello", ed_pk, sig)
    bcast = encode_header(TYPE_BROADCAST, sender, msg_id, 7, bcast_payload, flags=0)
    vectors["broadcast_hello"] = {
        "hex": bcast.hex(),
        "payload_hex": bcast_payload.hex(),
        "sign_message_hex": (msg_id + b"alice" + b"hello").hex(),
    }

    ack = encode_header(TYPE_ACK, sender, msg_id, 7, encode_ack_payload(bytes([0xAB] * 16)))
    vectors["ack"] = {"hex": ack.hex()}

    hs = encode_header(
        TYPE_HANDSHAKE, sender, msg_id, 7, encode_handshake_payload(1, b"\x00" * 32)
    )
    vectors["handshake_step1"] = {"hex": hs.hex()}

    raw_small = encode_header(TYPE_PRIVATE, sender, msg_id, 7, b"\x01ciphertext-demo")
    frags = fragment_packet(raw_small, msg_id, sender, 7, chunk=20)
    vectors["fragment_roundtrip"] = {
        "raw_hex": raw_small.hex(),
        "fragments_hex": [f.hex() for f in frags],
        "reassembled_hex": reassemble_fragments(
            [decode_header(f)["payload"] for f in frags]
        ).hex(),
    }

    media = encode_media_container(b"THUMB", b"JPEGDATA")
    vectors["media_container"] = {"hex": media.hex()}

    cqop = encode_cqop([b"\x01\x02", b"\x03"])
    vectors["cqop"] = {"hex": cqop.hex()}

    seed = bytes.fromhex("00" * 31 + "01")
    xseed = hkdf_sha256(seed, b"cqchat-v1-x25519")
    eseed = hkdf_sha256(seed, b"cqchat-v1-ed25519")
    # Vector uses ed25519_seed bytes standing in as a 32-byte public for stable hex
    vectors["hkdf"] = {
        "identity_seed_hex": seed.hex(),
        "x25519_seed_hex": xseed.hex(),
        "ed25519_seed_hex": eseed.hex(),
        "fingerprint_of_ed25519_seed_as_pk_hex": fingerprint(eseed).hex(),
    }
    vectors["spec"] = "protocol-v0.1"

    vectors["tcp_frame"] = {"hex": tcp_frame(empty).hex()}

    vectors["header_size"] = HEADER_SIZE
    vectors["version"] = VERSION

    out_dir = Path(__file__).resolve().parents[1] / "test-vectors"
    out = out_dir / "v0.1.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(vectors, indent=2) + "\n"
    out.write_text(payload)
    (out_dir / "v1.json").write_text(payload)  # alias during transition
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
