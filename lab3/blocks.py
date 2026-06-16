"""Block and transaction primitives for the Lab 3 PoW blockchain."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from ipv8.keyvault.crypto import default_eccrypto

HASH_SIZE = 32
# The header field is uint64 big-endian, but IPv8's "q" wire type is a signed
# int64 — keep nonces below 2^63 so both encodings agree.
NONCE_MASK = (1 << 63) - 1

# Difficulty (leading zero bits) every node mines at. With 3 miners this gives
# a new block every few seconds, fast enough to bury the test transaction.
DIFFICULTY = 25


def pack_header(prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int) -> bytes:
    """84-byte header: prev_hash | txs_hash | timestamp(8be) | difficulty(4be) | nonce(8be)."""
    return (
        prev_hash
        + txs_hash
        + timestamp.to_bytes(8, "big")
        + difficulty.to_bytes(4, "big")
        + nonce.to_bytes(8, "big")
    )


def leading_zero_bits(digest: bytes) -> int:
    return len(digest) * 8 - int.from_bytes(digest, "big").bit_length()


def meets_difficulty(block_hash: bytes, difficulty: int) -> bool:
    return leading_zero_bits(block_hash) >= difficulty


def txs_commitment(tx_hashes: list[bytes]) -> bytes:
    """Body commitment. Empty block -> SHA256(b"")."""
    return sha256(b"".join(tx_hashes)).digest()


@dataclass
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    @property
    def tx_hash(self) -> bytes:
        return sha256(
            self.sender_key + self.data + self.timestamp.to_bytes(8, "big") + self.signature
        ).digest()

    def verify(self) -> bool:
        try:
            key = default_eccrypto.key_from_public_bin(self.sender_key)
        except Exception:
            return False
        message = self.sender_key + self.data + self.timestamp.to_bytes(8, "big")
        return default_eccrypto.is_valid_signature(key, message, self.signature)


@dataclass
class Block:
    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    tx_hashes: list[bytes]

    def is_internally_valid(self) -> bool:
        """PoW holds, block_hash matches the header, and the body commitment matches."""
        if len(self.prev_hash) != HASH_SIZE or len(self.txs_hash) != HASH_SIZE:
            return False
        if self.height > 0 and self.difficulty < 1:
            return False
        header = pack_header(self.prev_hash, self.txs_hash, self.timestamp, self.difficulty, self.nonce)
        return (
            sha256(header).digest() == self.block_hash
            and meets_difficulty(self.block_hash, self.difficulty)
            and txs_commitment(self.tx_hashes) == self.txs_hash
        )


def make_block(height: int, prev_hash: bytes, tx_hashes: list[bytes],
               timestamp: int, difficulty: int, nonce: int) -> Block:
    txs_hash = txs_commitment(tx_hashes)
    header = pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)
    return Block(height, prev_hash, txs_hash, timestamp, difficulty, nonce,
                 sha256(header).digest(), tx_hashes)


def genesis_block() -> Block:
    """Fixed group-wide genesis; every node boots with this exact block 0."""
    return make_block(0, b"\x00" * HASH_SIZE, [], 0, 0, 0)
