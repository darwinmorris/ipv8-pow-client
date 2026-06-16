"""Unit tests for the chain primitives and wire payloads.

Run with: python test_chain.py
"""

from hashlib import sha256

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.messaging.serialization import default_serializer

from blocks import (
    Block,
    Transaction,
    genesis_block,
    leading_zero_bits,
    make_block,
    meets_difficulty,
    pack_header,
    txs_commitment,
)
from payloads import BlockResponse, SubmitTransaction


def test_header_packing():
    header = pack_header(b"\x01" * 32, b"\x02" * 32, 1718000000, 22, 12345)
    assert len(header) == 84
    assert header[:32] == b"\x01" * 32
    assert header[32:64] == b"\x02" * 32
    assert header[64:72] == (1718000000).to_bytes(8, "big")
    assert header[72:76] == (22).to_bytes(4, "big")
    assert header[76:84] == (12345).to_bytes(8, "big")


def test_leading_zero_bits():
    assert leading_zero_bits(b"\x00" * 32) == 256
    assert leading_zero_bits(b"\xff" + b"\x00" * 31) == 0
    assert leading_zero_bits(b"\x00\x0f" + b"\x00" * 30) == 12
    assert meets_difficulty(b"\x00\x0f" + b"\x00" * 30, 12)
    assert not meets_difficulty(b"\x00\x0f" + b"\x00" * 30, 13)


def test_empty_commitment():
    assert txs_commitment([]) == sha256(b"").digest()


def test_genesis():
    g1, g2 = genesis_block(), genesis_block()
    assert g1.block_hash == g2.block_hash  # deterministic across all nodes
    assert g1.height == 0
    assert g1.txs_hash == sha256(b"").digest()
    assert g1.is_internally_valid()


def test_transaction_hash_and_signature():
    key = default_eccrypto.generate_key("curve25519")
    sender_key = key.pub().key_to_bin()
    data, timestamp = b"hello lab3", 1718000000
    signature = default_eccrypto.create_signature(key, sender_key + data + timestamp.to_bytes(8, "big"))
    tx = Transaction(sender_key, data, timestamp, signature)
    assert tx.verify()
    assert tx.tx_hash == sha256(sender_key + data + timestamp.to_bytes(8, "big") + signature).digest()
    assert not Transaction(sender_key, data + b"!", timestamp, signature).verify()


def test_mine_and_validate_block():
    genesis = genesis_block()
    tx_hashes = [sha256(b"tx1").digest(), sha256(b"tx2").digest()]
    difficulty = 8
    nonce = 0
    while True:
        block = make_block(1, genesis.block_hash, tx_hashes, 1718000000, difficulty, nonce)
        if meets_difficulty(block.block_hash, difficulty):
            break
        nonce += 1
    assert block.is_internally_valid()
    assert block.txs_hash == sha256(tx_hashes[0] + tx_hashes[1]).digest()
    # tampering breaks validity
    tampered = Block(block.height, block.prev_hash, block.txs_hash, block.timestamp,
                     block.difficulty, block.nonce + 1, block.block_hash, block.tx_hashes)
    assert not tampered.is_internally_valid()


def test_payload_roundtrip():
    tx = SubmitTransaction(b"\x01" * 74, b"payload", 1718000000, b"\x02" * 64)
    packed = default_serializer.pack_serializable(tx)
    unpacked, _ = default_serializer.unpack_serializable(SubmitTransaction, packed)
    assert (unpacked.sender_key, unpacked.data, unpacked.timestamp, unpacked.signature) == \
           (tx.sender_key, tx.data, tx.timestamp, tx.signature)

    block = BlockResponse(3, b"\x0a" * 32, b"\x0b" * 32, 1718000000, 22, 999, b"\x0c" * 32, b"\x0d" * 64)
    packed = default_serializer.pack_serializable(block)
    unpacked, _ = default_serializer.unpack_serializable(BlockResponse, packed)
    assert unpacked.height == 3 and unpacked.nonce == 999 and unpacked.tx_hashes == b"\x0d" * 64


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all tests passed")
