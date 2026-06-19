"""Unit tests for multi-miner chain adoption.

Run with: PYTHONPATH=. pytest test/test_blockchain.py
"""

from __future__ import annotations

from unittest.mock import patch

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import Network
from ipv8.test.mocking.endpoint import AutoMockEndpoint

from src.blocks import genesis_block, make_block, meets_difficulty
from src.community import BlockchainCommunity, BlockchainSettings
from hashlib import sha256
from src.payloads import GetBlock, GetTransaction

BlockchainCommunity.community_id = b"\xab" * 20

AHEAD_BY = 5
TEST_DIFFICULTY = 8


def mine_chain(length: int, difficulty: int = TEST_DIFFICULTY) -> list:
    """Return a valid chain [genesis, block1, ..., block(length-1)]."""
    chain = [genesis_block()]

    for height in range(1, length):
        prev = chain[-1]
        nonce = 0

        while True:
            block = make_block(
                height,
                prev.block_hash,
                [],
                1_718_000_000 + height,
                difficulty,
                nonce,
            )

            if meets_difficulty(block.block_hash, difficulty):
                chain.append(block)
                break

            nonce += 1

    return chain


def make_community(
    member_keys: list[bytes],
    private_keys: list,
    my_index: int,
) -> BlockchainCommunity:
    endpoint = AutoMockEndpoint()
    endpoint.open()

    settings = BlockchainSettings(
        endpoint=endpoint,
        network=Network(),
        my_peer=Peer(private_keys[my_index], endpoint.wan_address),
        member_keys=member_keys,
        server_key=b"",
    )

    with patch.object(BlockchainCommunity, "register_task"):
        community = BlockchainCommunity(settings)

    community.my_estimated_wan = endpoint.wan_address
    community.my_estimated_lan = endpoint.lan_address

    return community


def install_chain(community: BlockchainCommunity, chain: list) -> None:
    community.blockchain.chain = list(chain)
    community.blockchain.chain_tx_hashes = {
        txh for block in chain for txh in block.tx_hashes
    }

    for block in chain:
        community.blockchain.block_pool[block.block_hash] = block


def connect_members(communities: list[BlockchainCommunity]) -> None:
    for left in communities:
        for right in communities:
            if left is right:
                continue

            peer = Peer(right.my_peer.public_key, right.endpoint.wan_address)
            left.network.add_verified_peer(peer)


def peer_for(community: BlockchainCommunity) -> Peer:
    return Peer(community.my_peer.public_key, community.my_peer.address)


def gossip_block(community: BlockchainCommunity, peer: Peer, block) -> None:
    community.handle_block(
        peer,
        block.height,
        block.prev_hash,
        block.txs_hash,
        block.timestamp,
        block.difficulty,
        block.nonce,
        b"".join(block.tx_hashes),
    )


def serve_blocks_from(leader: BlockchainCommunity, follower: BlockchainCommunity) -> None:
    """Simulate a teammate answering GetBlock requests while adoption runs."""
    leader_peer = peer_for(leader)

    def answer_request(height: int, peer: Peer | None = None) -> None:
        gossip_block(follower, leader_peer, leader.blockchain.chain[height])

    follower.request_block = answer_request  # type: ignore[method-assign]


def make_miners() -> tuple[list[bytes], list, list[BlockchainCommunity]]:
    private_keys = [default_eccrypto.generate_key("curve25519") for _ in range(3)]
    member_keys = [key.pub().key_to_bin() for key in private_keys]
    communities = [make_community(member_keys, private_keys, i) for i in range(3)]
    return member_keys, private_keys, communities


def test_lagging_miners_adopt_longer_chain():
    """When one miner is several blocks ahead, the others adopt its chain."""
    _keys, _private_keys, (leader, follower_a, follower_b) = make_miners()
    connect_members([leader, follower_a, follower_b])

    leader_chain = mine_chain(1 + AHEAD_BY)
    install_chain(leader, leader_chain)

    assert len(follower_a.blockchain.chain) == 1
    assert len(follower_b.blockchain.chain) == 1

    leader_peer = peer_for(leader)

    for block in leader_chain[1:]:
        gossip_block(follower_a, leader_peer, block)
        gossip_block(follower_b, leader_peer, block)

    for follower in (follower_a, follower_b):
        assert len(follower.blockchain.chain) == len(leader_chain)

        for height, expected in enumerate(leader_chain):
            assert follower.blockchain.chain[height].block_hash == expected.block_hash


def test_lagging_miner_catches_up_via_height_sync():
    """A miner behind by several blocks catches up when it polls a taller teammate."""
    _keys, _private_keys, (leader, follower, other) = make_miners()
    connect_members([leader, follower, other])

    leader_chain = mine_chain(1 + AHEAD_BY)
    install_chain(leader, leader_chain)
    serve_blocks_from(leader, follower)

    follower.request_block(leader_chain[-1].height, peer_for(leader))

    assert len(follower.blockchain.chain) == len(leader_chain)
    assert follower.blockchain.chain[-1].block_hash == leader_chain[-1].block_hash


def test_lagging_miner_adopts_when_tip_arrives_first():
    """Receiving the tip before its parents still ends on the longer chain."""
    _keys, _private_keys, (leader, follower, other) = make_miners()
    connect_members([leader, follower, other])

    leader_chain = mine_chain(1 + AHEAD_BY)
    install_chain(leader, leader_chain)
    serve_blocks_from(leader, follower)

    gossip_block(follower, peer_for(leader), leader_chain[-1])

    assert len(follower.blockchain.chain) == len(leader_chain)
    assert follower.blockchain.chain[-1].block_hash == leader_chain[-1].block_hash


def test_remember_missing_block_requests_once():
    _keys, _private_keys, (community, peer_owner, _other) = make_miners()
    peer = peer_for(peer_owner)

    sent = []
    community.ez_send = lambda peer, payload: sent.append((peer, payload))  # type: ignore[method-assign]

    community.remember_missing_block(3, peer)
    community.remember_missing_block(3, peer)

    assert community.missing_block_requests[3][1] == 1
    assert len(sent) == 1
    assert isinstance(sent[0][1], GetBlock)
    assert sent[0][1].height == 3


def test_remember_missing_transactions_requests_only_new_hashes():
    _keys, _private_keys, (community, peer_owner, _other) = make_miners()
    peer = peer_for(peer_owner)
    tx_hash = sha256(b"missing tx").digest()

    sent = []
    community.ez_send = lambda peer, payload: sent.append((peer, payload))  # type: ignore[method-assign]

    community.remember_missing_transactions([tx_hash], peer)
    community.remember_missing_transactions([tx_hash], peer)

    assert community.missing_tx_requests[tx_hash][1] == 1
    assert len(sent) == 1
    assert isinstance(sent[0][1], GetTransaction)
    assert sent[0][1].tx_hash == tx_hash


def test_retry_missing_block_uses_backoff_and_increments_retry_count():
    _keys, _private_keys, (community, _peer, _other) = make_miners()

    requested = []
    community.request_block = lambda height, peer=None: requested.append((height, peer))  # type: ignore[method-assign]

    community.missing_block_requests[4] = (0.0, 1)

    with patch("src.community.time.time", return_value=10.0):
        community.retry_missing_blocks()

    assert community.missing_block_requests[4][1] == 2
    assert requested == [(4, None)]


def test_retry_missing_transaction_uses_backoff_and_increments_retry_count():
    _keys, _private_keys, (community, _peer, _other) = make_miners()
    tx_hash = sha256(b"missing tx").digest()

    requested = []
    community.request_transactions = lambda tx_hashes, peer=None: requested.append((tx_hashes, peer))  # type: ignore[method-assign]

    community.missing_tx_requests[tx_hash] = (0.0, 1)

    with patch("src.community.time.time", return_value=10.0):
        community.retry_missing_transactions()

    assert community.missing_tx_requests[tx_hash][1] == 2
    assert requested == [([tx_hash], None)]


def test_retry_missing_transaction_removed_when_arrived():
    _keys, _private_keys, (community, _peer, _other) = make_miners()

    tx_hash = sha256(b"tx").digest()

    community.missing_tx_requests[tx_hash] = (0.0, 1)

    community.blockchain.chain_tx_hashes.add(tx_hash)

    community.retry_missing_transactions()

    assert tx_hash not in community.missing_tx_requests


if __name__ == "__main__":
    BlockchainCommunity.community_id = b"\xab" * 20

    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")

    print("all tests passed")