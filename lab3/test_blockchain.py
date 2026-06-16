"""Unit tests for multi-miner chain adoption.

Run with: python test_blockchain.py
"""

from __future__ import annotations

from unittest.mock import patch

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import Network
from ipv8.test.mocking.endpoint import AutoMockEndpoint

from community import BlockchainCommunity, BlockchainSettings
from blocks import genesis_block, make_block, meets_difficulty

AHEAD_BY = 5
TEST_DIFFICULTY = 8  # fast enough for unit tests; real nodes use blocks.DIFFICULTY


def mine_chain(length: int, difficulty: int = TEST_DIFFICULTY) -> list:
    """Return a valid chain [genesis, block1, ..., block(length-1)]."""
    chain = [genesis_block()]
    for height in range(1, length):
        prev = chain[-1]
        nonce = 0
        while True:
            block = make_block(height, prev.block_hash, [], 1_718_000_000 + height, difficulty, nonce)
            if meets_difficulty(block.block_hash, difficulty):
                chain.append(block)
                break
            nonce += 1
    return chain


def make_community(member_keys: list[bytes], private_keys: list, my_index: int) -> BlockchainCommunity:
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
    community.chain = list(chain)
    community.chain_tx_hashes = {txh for block in chain for txh in block.tx_hashes}
    for block in chain:
        community.block_pool[block.block_hash] = block


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
        gossip_block(follower, leader_peer, leader.chain[height])

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
    assert len(follower_a.chain) == 1
    assert len(follower_b.chain) == 1

    leader_peer = peer_for(leader)
    for block in leader_chain[1:]:
        gossip_block(follower_a, leader_peer, block)
        gossip_block(follower_b, leader_peer, block)

    for follower in (follower_a, follower_b):
        assert len(follower.chain) == len(leader_chain)
        for height, expected in enumerate(leader_chain):
            assert follower.chain[height].block_hash == expected.block_hash


def test_lagging_miner_catches_up_via_height_sync():
    """A miner behind by several blocks catches up when it polls a taller teammate."""
    _keys, _private_keys, (leader, follower, _other) = make_miners()
    connect_members([leader, follower, _other])

    leader_chain = mine_chain(1 + AHEAD_BY)
    install_chain(leader, leader_chain)
    serve_blocks_from(leader, follower)

    # Mirrors what happens after sync sees a teammate several blocks ahead.
    follower.request_block(leader_chain[-1].height, peer_for(leader))

    assert len(follower.chain) == len(leader_chain)
    assert follower.chain[-1].block_hash == leader_chain[-1].block_hash


def test_lagging_miner_adopts_when_tip_arrives_first():
    """Receiving the tip before its parents still ends on the longer chain."""
    _keys, _private_keys, (leader, follower, _other) = make_miners()
    connect_members([leader, follower, _other])

    leader_chain = mine_chain(1 + AHEAD_BY)
    install_chain(leader, leader_chain)
    serve_blocks_from(leader, follower)

    gossip_block(follower, peer_for(leader), leader_chain[-1])

    assert len(follower.chain) == len(leader_chain)
    assert follower.chain[-1].block_hash == leader_chain[-1].block_hash


if __name__ == "__main__":
    BlockchainCommunity.community_id = b"\xab" * 20
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all tests passed")
