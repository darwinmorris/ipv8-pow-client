"""Blockchain community: chain state, mining, block gossip, and server query handlers.

All 3 nodes mine concurrently. Consensus is longest chain; ties at equal height
are broken by the smaller block hash so the group converges deterministically.
"""

from __future__ import annotations

import asyncio
import random
import time
from hashlib import sha256

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.peer import Peer

from blocks import (
    DIFFICULTY,
    HASH_SIZE,
    NONCE_MASK,
    Block,
    Transaction,
    genesis_block,
    meets_difficulty,
    pack_header,
    txs_commitment,
)
from payloads import (
    BlockResponse,
    ChainHeightResponse,
    GetBlock,
    GetChainHeight,
    NewBlockGossip,
    SubmitTransaction,
    SubmitTransactionResponse,
    TransactionGossip,
)

NONCE_BATCH = 20_000      # hashes per event-loop yield while mining
SYNC_INTERVAL = 5.0       # seconds between tip polls to teammates


class BlockchainSettings(CommunitySettings):
    member_keys: list = None  # the 3 members' public keys (bytes)
    server_key: bytes = b""


class BlockchainCommunity(Community):
    community_id = b""  # set in main.py before IPv8 starts
    settings_class = BlockchainSettings

    def __init__(self, settings: BlockchainSettings) -> None:
        super().__init__(settings)
        self.member_keys: list[bytes] = settings.member_keys
        self.server_key: bytes = settings.server_key

        self.chain: list[Block] = [genesis_block()]
        self.block_pool: dict[bytes, Block] = {}        # valid blocks not (yet) on our chain
        self.mempool: dict[bytes, Transaction] = {}
        self.chain_tx_hashes: set[bytes] = set()

        self.add_message_handler(SubmitTransaction, self.on_submit_transaction)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(BlockResponse, self.on_block_response)
        self.add_message_handler(ChainHeightResponse, self.on_chain_height_response)
        self.add_message_handler(NewBlockGossip, self.on_new_block)
        self.add_message_handler(TransactionGossip, self.on_transaction_gossip)

        self.register_task("mine", self.mine_forever)
        self.register_task("sync", self.sync_with_teammates, interval=SYNC_INTERVAL)

    # --- peer filtering -----------------------------------------------------

    def is_member(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() in self.member_keys

    def is_trusted(self, peer: Peer) -> bool:
        return self.is_member(peer) or peer.public_key.key_to_bin() == self.server_key

    def member_peers(self) -> list[Peer]:
        return [p for p in self.get_peers() if self.is_member(p)]

    # --- server query handlers ----------------------------------------------
    
    @lazy_wrapper(SubmitTransaction)
    def on_submit_transaction(self, peer: Peer, payload: SubmitTransaction) -> None:
        if not self.is_trusted(peer):
            return
        tx = Transaction(payload.sender_key, payload.data, payload.timestamp, payload.signature)
        if tx.verify():
            if self.accept_transaction(tx):
                self.gossip_to_members(
                    TransactionGossip(tx.sender_key, tx.data, tx.timestamp, tx.signature)
                )
            self.ez_send(peer, SubmitTransactionResponse(True, tx.tx_hash, "accepted"))
            print(f"[tx] accepted {tx.tx_hash.hex()[:16]} from server")
        else:
            self.ez_send(peer, SubmitTransactionResponse(False, tx.tx_hash, "invalid signature"))
            print("[tx] rejected transaction with invalid signature")

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer: Peer, payload: GetChainHeight) -> None:
        if not self.is_trusted(peer):
            return
        self.ez_send(peer, ChainHeightResponse(payload.request_id, len(self.chain) - 1,
                                               self.chain[-1].block_hash))

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer: Peer, payload: GetBlock) -> None:
        if not self.is_trusted(peer) or not 0 <= payload.height < len(self.chain):
            return
        block = self.chain[payload.height]
        self.ez_send(peer, BlockResponse(block.height, block.prev_hash, block.txs_hash,
                                         block.timestamp, block.difficulty, block.nonce,
                                         block.block_hash, b"".join(block.tx_hashes)))

    # --- intra-group messages -------------------------------------------------

    @lazy_wrapper(TransactionGossip)
    def on_transaction_gossip(self, peer: Peer, payload: TransactionGossip) -> None:
        if not self.is_member(peer):
            return
        tx = Transaction(payload.sender_key, payload.data, payload.timestamp, payload.signature)

        if not tx.verify():
            return

        if self.accept_transaction(tx):
            self.gossip_to_members(
                TransactionGossip(tx.sender_key, tx.data, tx.timestamp, tx.signature),
                exclude=peer,
            )

    @lazy_wrapper(NewBlockGossip)
    def on_new_block(self, peer: Peer, payload: NewBlockGossip) -> None:
        if self.is_member(peer):
            self.handle_block(peer, payload.height, payload.prev_hash, payload.txs_hash,
                              payload.timestamp, payload.difficulty, payload.nonce,
                              payload.tx_hashes)

    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer: Peer, payload: BlockResponse) -> None:
        if self.is_member(peer):
            self.handle_block(peer, payload.height, payload.prev_hash, payload.txs_hash,
                              payload.timestamp, payload.difficulty, payload.nonce,
                              payload.tx_hashes)

    def sync_with_teammates(self) -> None:
        for member in self.member_peers():
            self.ez_send(member, GetChainHeight(random.getrandbits(63)))

    @lazy_wrapper(ChainHeightResponse)
    def on_chain_height_response(self, peer: Peer, payload: ChainHeightResponse) -> None:
        """Periodic tip poll: if a teammate is ahead of us, fetch their tip block."""
        if not self.is_member(peer):
            return
        if payload.height >= len(self.chain) - 1 and payload.tip_hash not in self.block_pool:
            self.request_block(payload.height, peer)

    # --- chain state ----------------------------------------------------------

    def accept_transaction(self, tx: Transaction) -> bool:
        if tx.tx_hash in self.chain_tx_hashes:
            return False

        if tx.tx_hash in self.mempool:
            return False

        self.mempool[tx.tx_hash] = tx
        return True

    def pending_tx_hashes(self) -> list[bytes]:
        return [txh for txh in self.mempool if txh not in self.chain_tx_hashes]

    def handle_block(self, peer: Peer, height: int, prev_hash: bytes, txs_hash: bytes,
                     timestamp: int, difficulty: int, nonce: int, tx_hashes_blob: bytes) -> None:
        if height < 1 or len(tx_hashes_blob) % HASH_SIZE != 0:
            return
        tx_hashes = [tx_hashes_blob[i:i + HASH_SIZE] for i in range(0, len(tx_hashes_blob), HASH_SIZE)]
        # Recompute the hash from the header; never trust a received block_hash.
        block_hash = sha256(pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)).digest()
        block = Block(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes)
        if block.block_hash in self.block_pool or not block.is_internally_valid():
            return
        self.block_pool[block.block_hash] = block # we need to double check whether or not to add transactions
        self.try_adopt(peer)

    def try_adopt(self, peer: Peer | None = None) -> None:
        """Adopt the best chain reachable through pooled blocks; request missing parents."""
        for block in sorted(self.block_pool.values(), key=lambda b: (-b.height, b.block_hash)):
            if block.height <= len(self.chain) - 1 and \
                    self.chain[block.height].block_hash == block.block_hash:
                continue  # already on our chain
            branch, fork_point, missing = self.trace_branch(block)
            if fork_point is None:
                if missing is not None:
                    self.request_block(missing, peer)
                continue
            tip = self.chain[-1]
            longer = block.height > tip.height
            tie_win = block.height == tip.height and block.block_hash < tip.block_hash
            if longer or tie_win:
                self.chain = self.chain[:fork_point + 1] + list(reversed(branch))
                self.chain_tx_hashes = {txh for b in self.chain for txh in b.tx_hashes}
                print(f"[chain] height {block.height}, tip {block.block_hash.hex()[:16]} "
                        f"(fork point {fork_point})")
                break
        # keep the pool small
        cutoff = len(self.chain) - 10
        for block_hash in [h for h, b in self.block_pool.items() if b.height < cutoff]:
            del self.block_pool[block_hash]

    def trace_branch(self, block: Block):
        """Walk prev_hash links from `block` down to our chain.

        Returns (branch tip->child-of-fork-point, fork_point height, missing height).
        """
        branch = []
        cur = block
        while True:
            branch.append(cur)
            parent_height = cur.height - 1
            if parent_height < len(self.chain) and \
                    self.chain[parent_height].block_hash == cur.prev_hash:
                return branch, parent_height, None
            parent = self.block_pool.get(cur.prev_hash)
            if parent is None or parent.height != parent_height:
                return branch, None, parent_height if parent_height >= 1 else None
            cur = parent

    def request_block(self, height: int, peer: Peer | None = None) -> None:
        targets = [peer] if peer is not None and self.is_member(peer) else self.member_peers()
        for target in targets:
            self.ez_send(target, GetBlock(height))
    
    def gossip_to_members(self, payload, exclude: Peer | None = None) -> None:
        for member in self.member_peers():
            if exclude is not None and member == exclude:
                continue
            self.ez_send(member, payload)

    # --- mining ---------------------------------------------------------------

    async def mine_forever(self) -> None:
        while True:
            await self.mine_one_block()
            await asyncio.sleep(0)

    async def mine_one_block(self) -> None:
        """Mine on the current tip; bail out when the tip or the mempool changes."""
        tip = self.chain[-1]
        height = len(self.chain)
        pending = self.pending_tx_hashes()
        txs_hash = txs_commitment(pending)
        timestamp = int(time.time())
        prefix = tip.block_hash + txs_hash + timestamp.to_bytes(8, "big") + DIFFICULTY.to_bytes(4, "big")
        nonce = random.getrandbits(63)  # random start so the 3 miners search disjoint ranges

        while True:
            for _ in range(NONCE_BATCH):
                digest = sha256(prefix + nonce.to_bytes(8, "big")).digest()
                if meets_difficulty(digest, DIFFICULTY):
                    block = Block(height, tip.block_hash, txs_hash, timestamp,
                                  DIFFICULTY, nonce, digest, pending)
                    self.adopt_own_block(block)
                    return
                nonce = (nonce + 1) & NONCE_MASK
            await asyncio.sleep(0)
            if self.chain[-1] is not tip or self.pending_tx_hashes() != pending:
                return  # restart on the new tip / with the new transactions

    def adopt_own_block(self, block: Block) -> None:
        self.block_pool[block.block_hash] = block

        tip = self.chain[-1]
        if block.prev_hash == tip.block_hash:
            self.chain.append(block)
            self.chain_tx_hashes.update(block.tx_hashes)
        else:
            self.try_adopt()  # prevent race condition where we adopted a block during the mining process

        print(f"[mine] found block {block.height} {block.block_hash.hex()[:16]} "
              f"({len(block.tx_hashes)} txs)")
        gossip = NewBlockGossip(block.height, block.prev_hash, block.txs_hash, block.timestamp,
                                block.difficulty, block.nonce, b"".join(block.tx_hashes))
        
        self.gossip_to_members(gossip)
