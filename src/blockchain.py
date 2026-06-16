from __future__ import annotations

from dataclasses import dataclass, field

from src.core import Block, make_genesis, mine_block, validate_chain, tx_hash


@dataclass(frozen=True)
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    @property
    def hash(self) -> bytes:
        return tx_hash(
            self.sender_key,
            self.data,
            self.timestamp,
            self.signature,
        )


@dataclass
class Blockchain:
    difficulty: int = 8
    chain: list[Block] = field(default_factory=list)
    mempool: list[Transaction] = field(default_factory=list)

    def __post_init__(self):
        if not self.chain:
            self.chain.append(make_genesis(self.difficulty))

    @property
    def height(self) -> int:
        return self.chain[-1].height

    @property
    def tip(self) -> Block:
        return self.chain[-1]

    @property
    def tip_hash(self) -> bytes:
        return self.tip.block_hash

    def add_transaction(self, tx: Transaction) -> bytes:
        txh = tx.hash
        # maybe we store mempool seen hash in bc and not node
        if any(existing.hash == txh for existing in self.mempool):
            return txh

        self.mempool.append(tx)
        return txh

    def mine_next_block(self) -> Block:
        txs = list(self.mempool)
        tx_hashes = [tx.hash for tx in txs]

        block = mine_block(
            height=self.height + 1,
            prev_hash=self.tip_hash,
            tx_hashes_=tx_hashes,
            difficulty=self.difficulty,
        )

        self.chain.append(block)

        self.remove_from_mempool(tx_hashes)

        validate_chain(self.chain)
        return block

    def get_block(self, height: int) -> Block:
        if height < 0 or height >= len(self.chain):
            raise IndexError("block height out of range")
        return self.chain[height]

    def validate(self) -> None:
        validate_chain(self.chain)

    def remove_from_mempool(self, tx_hashes: list[bytes]) -> None:
        mined_hashes = set(tx_hashes)
        self.mempool = [
            tx for tx in self.mempool
            if tx.hash not in mined_hashes
        ]