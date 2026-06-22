"""Block and transaction primitives for the Lab 3 PoW blockchain.

This file carries the combined bonus implementation:

* Bonus 4 (fork convergence after a partition): work-based fork choice,
  bounded reorg depth, and an atomic branch switch that returns orphaned
  transactions to the mempool. See ``try_adopt`` / ``switch_chain``.
* Bonus 5 (adaptive difficulty): a deterministic retargeting controller and a
  median-time-past timestamp rule. See ``expected_difficulty`` /
  ``median_time_past``.

The two fit together: adaptive difficulty makes per-block difficulty vary, and
work-based fork choice is exactly what is needed to compare variable-difficulty
branches correctly.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from hashlib import sha256

from ipv8.keyvault.crypto import default_eccrypto

HASH_SIZE = 32
# The header field is uint64 big-endian, but IPv8's "q" wire type is a signed
# int64 — keep nonces below 2^63 so both encodings agree.
NONCE_MASK = (1 << 63) - 1

# Bootstrap difficulty (leading zero bits): used for the first DIFFICULTY_WINDOW
# blocks, before there is enough history to retarget. After that the adaptive
# controller (Bonus 5) takes over.
DIFFICULTY = 25

RETRY_INITIAL_DELAY = 2.0
RETRY_MAX_DELAY = 30.0
MAX_RETRIES = 5

# --- Bonus 4: fork convergence after a partition ---------------------------
#
# A branch is never chosen on length alone. Length is trivial to fake: a peer
# can splice many low-difficulty blocks together for almost no cost and hand you
# a chain that is "longer" but carries no real work. We choose the branch with
# the most accumulated proof-of-work, and (with Bonus 5) we also require every
# block to use the difficulty the retarget schedule mandates — so a fake branch
# would have to do the same real work as the honest one to compete.

# A reorg is the act of rolling back our own confirmed blocks to follow a
# competing branch. We cap how far back that can reach. A partition that heals
# legitimately needs only as deep a reorg as the partition was long; an attacker
# trying to rewrite ancient history needs an unbounded one. Bounding the depth
# keeps a single bad peer from rewriting the whole ledger and keeps the rebuild
# cheap. Sized for several minutes of partition at our block rate.
MAX_REORG_DEPTH = 256

# --- Bonus 5: adaptive difficulty ------------------------------------------
#
# We want a steady block interval through a tenfold swing in hashpower, settling
# without oscillation, and unmovable by one miner lying about timestamps.
# ``expected_difficulty`` estimates the network hashrate from recent blocks and
# aims straight at the equilibrium difficulty; taking the MEDIAN of the per-block
# estimates makes it deaf to a single liar, and clamping each solve time bounds
# how far one timestamp can reach. ``median_time_past`` rejects backdating, and
# ``MAX_FUTURE_TIME`` rejects blocks that are far ahead of the receiver's clock.
TARGET_BLOCK_TIME = 10.0   # seconds we want between blocks
DIFFICULTY_WINDOW = 11     # blocks of history the retarget looks at
SOLVE_CLAMP_LOW = 1.0      # a counted solve time is never below this...
SOLVE_CLAMP_HIGH = 6 * TARGET_BLOCK_TIME  # ...nor above this (caps a liar's reach)
MEDIAN_TIME_BLOCKS = 11    # window for the median-time-past timestamp rule
MIN_DIFFICULTY = 4         # floor: never mine/accept below this
MAX_DIFFICULTY = 48        # ceiling on difficulty
MAX_FUTURE_TIME = 120      # reject peer block times more than this many seconds ahead


def block_work(difficulty: int) -> int:
    """Expected hashes to mine a block at this difficulty == 2**difficulty.

    Summed over a chain this gives total accumulated work, the quantity two
    competing branches are actually compared on.
    """
    return 1 << max(difficulty, 0)


def chain_work(blocks: list["Block"]) -> int:
    return sum(block_work(b.difficulty) for b in blocks)


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def expected_difficulty(chain: list["Block"]) -> int:
    """Difficulty the next block (the one extending `chain`) must use.

    Deterministic and identical on every node, so the whole group mines at the
    same adaptive difficulty without exchanging a single extra message. We
    recover a hashrate estimate from each recent block (a block of difficulty D
    solved in `st` seconds implies 2**D / st hashes/s), take the median over a
    window (robust to one liar), and pick the difficulty whose expected solve
    time equals the target. Aiming at the equilibrium rather than nudging a
    controller means no overshoot and no ringing.
    """
    real = [b for b in chain if b.height >= 1]  # genesis has a placeholder ts
    if len(real) <= DIFFICULTY_WINDOW:
        return DIFFICULTY  # bootstrap: not enough history to retarget yet

    window = real[-(DIFFICULTY_WINDOW + 1):]
    hashrate_samples = []
    for prev, cur in zip(window, window[1:]):
        solve = cur.timestamp - prev.timestamp
        solve = min(max(float(solve), SOLVE_CLAMP_LOW), SOLVE_CLAMP_HIGH)
        hashrate_samples.append(block_work(cur.difficulty) / solve)

    hashrate = _median(hashrate_samples)
    difficulty = round(math.log2(hashrate * TARGET_BLOCK_TIME))
    return max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, int(difficulty)))


def median_time_past(chain: list["Block"]) -> int:
    """Median of the most recent real-block timestamps.

    A new block must be strictly newer than this, which neutralises a miner that
    backdates its clock: the median of the window is robust to a single outlier.
    """
    stamps = [b.timestamp for b in chain if b.height >= 1][-MEDIAN_TIME_BLOCKS:]
    if not stamps:
        return 0
    return sorted(stamps)[len(stamps) // 2]


def timestamp_is_valid(chain: list["Block"], timestamp: int, now: int | None = None) -> bool:
    """A block timestamp must move forward and not be far ahead of local time."""
    if timestamp <= median_time_past(chain):
        return False
    if now is None:
        now = int(time.time())
    return timestamp <= now + MAX_FUTURE_TIME


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


def serialize_transaction(tx: Transaction) -> bytes:
    """Length-prefixed wire encoding for one transaction body."""
    return (
        len(tx.sender_key).to_bytes(2, "big") + tx.sender_key
        + len(tx.data).to_bytes(4, "big") + tx.data
        + tx.timestamp.to_bytes(8, "big")
        + len(tx.signature).to_bytes(2, "big") + tx.signature
    )


def deserialize_transaction(data: bytes, offset: int = 0) -> tuple[Transaction, int]:
    key_len = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    sender_key = data[offset:offset + key_len]
    offset += key_len
    data_len = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    payload = data[offset:offset + data_len]
    offset += data_len
    timestamp = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    sig_len = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    signature = data[offset:offset + sig_len]
    offset += sig_len
    return Transaction(sender_key, payload, timestamp, signature), offset


def pack_transactions(transactions: list[Transaction]) -> bytes:
    return b"".join(serialize_transaction(tx) for tx in transactions)


def unpack_transactions(data: bytes) -> list[Transaction]:
    txs: list[Transaction] = []
    offset = 0
    while offset < len(data):
        tx, offset = deserialize_transaction(data, offset)
        txs.append(tx)
    return txs


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
    transactions: list[Transaction] = field(default_factory=list)
    pending_tx_hashes: list[bytes] = field(default_factory=list)

    @property
    def tx_hashes(self) -> list[bytes]:
        if self.transactions:
            return [tx.tx_hash for tx in self.transactions]
        return self.pending_tx_hashes

    def transaction_by_hash(self, tx_hash: bytes) -> Transaction | None:
        for tx in self.transactions:
            if tx.tx_hash == tx_hash:
                return tx
        return None

    def is_internally_valid(self) -> bool:
        """PoW holds, block_hash matches the header, and the body commitment matches."""
        if len(self.prev_hash) != HASH_SIZE or len(self.txs_hash) != HASH_SIZE:
            return False
        # Reject blocks that do not clear the difficulty floor (height 0 is the
        # fixed group genesis and is exempt). This is the first line of defence
        # against a "longer but fake" branch built from cheap, low-work blocks.
        if self.height > 0 and self.difficulty < MIN_DIFFICULTY:
            return False
        if self.transactions:
            if len(self.transactions) != len(self.tx_hashes):
                return False
            if [tx.tx_hash for tx in self.transactions] != self.tx_hashes:
                return False
        header = pack_header(self.prev_hash, self.txs_hash, self.timestamp, self.difficulty, self.nonce)
        return (
            sha256(header).digest() == self.block_hash
            and meets_difficulty(self.block_hash, self.difficulty)
            and txs_commitment(self.tx_hashes) == self.txs_hash
        )


def make_block(height: int, prev_hash: bytes, tx_hashes: list[bytes],
               timestamp: int, difficulty: int, nonce: int,
               transactions: list[Transaction] | None = None) -> Block:
    txs = list(transactions) if transactions else []
    if txs:
        tx_hashes = [tx.tx_hash for tx in txs]
    txs_hash = txs_commitment(tx_hashes)
    header = pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)
    block_hash = sha256(header).digest()
    if txs:
        return Block(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, txs)
    return Block(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash,
                 pending_tx_hashes=list(tx_hashes))


def genesis_block() -> Block:
    """Fixed group-wide genesis; every node boots with this exact block 0."""
    return make_block(0, b"\x00" * HASH_SIZE, [], 0, 0, 0)

class Blockchain:
    def __init__(self):
        self.chain: list[Block] = [genesis_block()]
        self.block_pool: dict[bytes, Block] = {}
        self.mempool: dict[bytes, Transaction] = {}
        self.chain_tx_hashes: set[bytes] = set()
        # Bonus 4 telemetry: how many reorgs we have performed, the depth of the
        # last one, and how many transactions the last reorg returned to the
        # mempool. Useful for the convergence demo/tests and for proving that no
        # transaction is lost when we switch branches.
        self.reorg_count: int = 0
        self.last_reorg_depth: int = 0
        self.last_orphaned_txs: list[bytes] = []
       

    @property
    def height(self) -> int:
        return len(self.chain) - 1

    @property
    def tip(self) -> Block:
        return self.chain[-1]

    @property
    def total_work(self) -> int:
        """Accumulated proof-of-work of the active chain (the fork-choice metric)."""
        return chain_work(self.chain)

    def next_difficulty(self) -> int:
        """Difficulty the next mined block must declare (the adaptive target)."""
        return expected_difficulty(self.chain)

    def valid_difficulty_and_time(self, kept_prefix: list[Block], branch_blocks: list[Block]) -> bool:
        """Every block in the branch must use the mandated difficulty and a sane timestamp.

        This turns the adaptive controller into a *consensus rule*: a miner cannot
        declare an easier difficulty than the schedule allows (which would also be
        the cheap way to fake a "longer" branch), backdate a block to skew the
        retarget, or future-date it far beyond the receiver's clock. The schedule
        and median-time-past checks depend only on prior blocks, so they are
        deterministic across nodes; the future-time window is a local admission
        guard with slack for ordinary clock skew.
        """
        prefix = list(kept_prefix)
        for block in branch_blocks:
            if block.difficulty != expected_difficulty(prefix):
                return False
            if not timestamp_is_valid(prefix, block.timestamp):
                return False
            prefix.append(block)
        return True

    def accept_transaction(self, tx: Transaction) -> bool:
        if tx.tx_hash in self.chain_tx_hashes:
            return False

        if tx.tx_hash in self.mempool:
            return False

        self.mempool[tx.tx_hash] = tx
        return True

    def pending_tx_hashes(self) -> list[bytes]:
        return list(self.mempool.keys())

    def find_transaction(self, tx_hash: bytes) -> Transaction | None:
        """Look up a transaction in the mempool, active chain, or block pool."""
        tx = self.mempool.get(tx_hash)
        if tx is not None:
            return tx
        for block in self.chain:
            tx = block.transaction_by_hash(tx_hash)
            if tx is not None:
                return tx
        for block in self.block_pool.values():
            tx = block.transaction_by_hash(tx_hash)
            if tx is not None:
                return tx
        return None

    def complete_block_transactions(self, block: Block) -> Block:
        """Attach full transaction bodies to a block when every hash is known."""
        if block.transactions and len(block.transactions) == len(block.tx_hashes):
            if all(tx.tx_hash == h for tx, h in zip(block.transactions, block.tx_hashes)):
                return block

        txs: list[Transaction] = []
        for tx_hash in block.tx_hashes:
            tx = block.transaction_by_hash(tx_hash) or self.find_transaction(tx_hash)
            if tx is None:
                return block
            txs.append(tx)

        return Block(
            block.height, block.prev_hash, block.txs_hash, block.timestamp,
            block.difficulty, block.nonce, block.block_hash, txs,
        )

    def validate_block_transactions(self, block: Block) -> tuple[bool, list[bytes]]:
        # Only the position-independent checks live here: no duplicate hashes
        # inside the block, and every referenced tx is known and validly signed.
        # We deliberately do NOT reject a tx just because it is already in our
        # active chain — a competing fork may re-include it because the blocks
        # holding it are about to be rolled back. That double-spend decision is
        # context-dependent and is made against the post-fork chain in try_adopt.
        if len(block.tx_hashes) != len(set(block.tx_hashes)):
            return False, []

        missing_txs = []

        for tx_hash in block.tx_hashes:
            tx = block.transaction_by_hash(tx_hash) or self.find_transaction(tx_hash)

            if tx is None:
                missing_txs.append(tx_hash)
                continue

            if not tx.verify():
                return False, []

        return True, missing_txs


    def add_block(self, block: Block) -> tuple[bool, int | None, list[bytes]]:
        if block.block_hash in self.block_pool:
            return False, None, []

        if not block.is_internally_valid():
            return False, None, []

        block = self.complete_block_transactions(block)
        txs_valid, missing_txs = self.validate_block_transactions(block)

        if not txs_valid:
            return False, None, []

        self.block_pool[block.block_hash] = block

        if missing_txs:
            return False, None, missing_txs
        
        missing_block = self.try_adopt()
        return True, missing_block, []

    def branch_double_spend(self, fork_point: int, branch_blocks: list[Block]) -> bool:
        """Would this branch put the same transaction in the chain twice?

        We measure against the chain the branch would actually create: the prefix
        we keep (chain[:fork_point + 1]) plus the branch blocks themselves. The
        blocks above the fork point are rolled back, so any tx they hold is freed
        and a fork is free to re-include it without it counting as a double-spend.
        """
        seen = {txh for b in self.chain[:fork_point + 1] for txh in b.tx_hashes}
        for block in branch_blocks:
            for tx_hash in block.tx_hashes:
                if tx_hash in seen:
                    return True
                seen.add(tx_hash)
        return False

    def branch_transactions_available(self, branch_blocks: list[Block]) -> bool:
        """Every block we would adopt must reference known, valid transactions."""
        for block in branch_blocks:
            txs_valid, missing_txs = self.validate_block_transactions(block)
            if not txs_valid or missing_txs:
                return False
        return True

    def try_adopt(self) -> int | None:
        """Pick the heaviest valid branch reachable from the block pool.

        Combined-bonus fork choice:

        * Every block in a candidate branch must obey the adaptive difficulty
          schedule and the median-time-past timestamp rule (Bonus 5), so a branch
          of cheap off-schedule blocks or one built on backdated timestamps is
          rejected before it is ever considered.
        * Branches are compared on accumulated proof-of-work, not on length, so a
          longer chain made of cheaper blocks cannot displace a heavier honest one
          (Bonus 4).
        * A reorg deeper than ``MAX_REORG_DEPTH`` is refused outright, bounding
          how much history any single peer can make us rewrite (Bonus 4).
        * The switch is one atomic rebind of ``self.chain``; transactions stranded
          on the abandoned blocks are returned to the mempool in the same step, so
          no transaction is ever lost across a fork (Bonus 4).
        """
        missing_height = None
        current_work = self.total_work
        best_candidate: tuple[list[Block], list[Block]] | None = None
        best_work = current_work
        best_tip_hash = self.tip.block_hash

        for block in sorted(self.block_pool.values(), key=lambda b: (-b.height, b.block_hash)):
            if block.height <= self.height and self.chain[block.height].block_hash == block.block_hash:
                continue

            txs_valid, missing_txs = self.validate_block_transactions(block)

            if not txs_valid or missing_txs:
                continue

            branch, fork_point, missing = self.trace_branch(block)

            if fork_point is None:
                if missing is not None:
                    if missing_height is None:
                        missing_height = missing
                continue

            branch_blocks = list(reversed(branch))
            kept_prefix = self.chain[:fork_point + 1]

            # A tip can arrive before its parent, and a parent can arrive before
            # all of its transaction bodies. Validate the whole branch here so a
            # clean tip cannot accidentally pull in an earlier block whose tx data
            # is still missing.
            if not self.branch_transactions_available(branch_blocks):
                continue

            # Bonus 5: a branch is only legal if every block uses the difficulty
            # the retarget mandates for its position and carries a timestamp past
            # the median time. This stops cheap off-schedule blocks and backdating.
            if not self.valid_difficulty_and_time(kept_prefix, branch_blocks):
                continue

            # Bound the reorg: never roll back more than MAX_REORG_DEPTH of our
            # own confirmed blocks. A legitimately healed partition stays well
            # within this; a peer trying to rewrite ancient history does not.
            reorg_depth = self.height - fork_point
            if reorg_depth > MAX_REORG_DEPTH:
                continue

            # Reject a branch only if it genuinely double-spends within the chain
            # it would create — not just because the tx still sits in the chain we
            # are about to abandon. Without this, two miners that each mine the
            # same transaction at the same height stay stuck on their own block:
            # neither can ever adopt the other's competing branch.
            if self.branch_double_spend(fork_point, branch_blocks):
                continue

            prospective_work = chain_work(kept_prefix) + chain_work(branch_blocks)

            # Examine every reachable candidate before switching. With adaptive
            # difficulty, a shorter branch can carry more work than a taller one,
            # so height-sorted iteration is only a fetch/validation convenience,
            # not the fork-choice rule.
            if prospective_work < best_work:
                continue
            if prospective_work == best_work and block.block_hash >= best_tip_hash:
                continue

            best_candidate = (kept_prefix, branch_blocks)
            best_work = prospective_work
            best_tip_hash = block.block_hash

        if best_candidate is not None:
            kept_prefix, branch_blocks = best_candidate
            self.switch_chain(kept_prefix, branch_blocks)

        # Keep the pool deep enough to assemble a full MAX_REORG_DEPTH reorg, but
        # drop anything older so memory stays bounded.
        cutoff = self.height - MAX_REORG_DEPTH
        for block_hash in [h for h, b in self.block_pool.items() if b.height < cutoff]:
            del self.block_pool[block_hash]

        return missing_height

    def switch_chain(self, kept_prefix: list[Block], branch_blocks: list[Block]) -> None:
        """Atomically replace the active chain and return orphaned txs to the mempool.

        The whole switch is a single rebind of ``self.chain`` followed by a
        rebuild of the confirmed-tx index, so an observer never sees a partial
        chain. Any transaction that was confirmed on a block we are discarding
        but is absent from the branch we adopt is put back into the mempool, so
        it can be mined again and is never silently dropped.
        """
        old_blocks_above_fork = self.chain[len(kept_prefix):]

        new_chain = kept_prefix + branch_blocks
        new_tx_hashes = {txh for b in new_chain for txh in b.tx_hashes}

        # Atomic publish of the new tip + its confirmed-tx set.
        self.chain = new_chain
        self.chain_tx_hashes = new_tx_hashes

        for txh in new_tx_hashes:
            self.mempool.pop(txh, None)

        orphaned = []
        for stale_block in old_blocks_above_fork:
            for txh in stale_block.tx_hashes:
                if txh in new_tx_hashes:
                    continue  # the branch already re-included it
                tx = stale_block.transaction_by_hash(txh)
                if tx is not None:
                    self.mempool[txh] = tx
                    orphaned.append(txh)

        if old_blocks_above_fork:  # a genuine rollback, not a plain extension
            self.reorg_count += 1
            self.last_reorg_depth = len(old_blocks_above_fork)
            self.last_orphaned_txs = orphaned

    def trace_branch(self, block: Block):
        branch = []
        cur = block

        while True:
            branch.append(cur)
            parent_height = cur.height - 1

            if parent_height < len(self.chain) and self.chain[parent_height].block_hash == cur.prev_hash:
                return branch, parent_height, None

            parent = self.block_pool.get(cur.prev_hash)

            if parent is None or parent.height != parent_height:
                return branch, None, parent_height if parent_height >= 1 else None

            cur = parent
