# Design Overview 
## Architecture
The system implements a simple proof-of-work blockchain using IPv8 peer-to-peer communication. Miner nodes participate in the network and concurrently mine blocks containing transactions submitted by a trusted server.

Each node maintains:
- A local blockchain
- A mempool of pending transactions
- A pool of known blocks not yet on the chain

Transactions are propagated between miners using gossip messages, while blocks are disseminated immediately after being mined.

## Consensus
Nodes follow a longest-chain consensus protocol.

On receiving a block:
- Block header and PoW are validated
- Block is stored in the local block pool.
- The node attempts to reconstruct the best chain reachable through known blocks.
- The longest valid chain is selected as the active chain


If two chains have equal height, ties are broken deterministically by selecting the chain whose tip block has the smaller hash value. This ensures that all nodes eventually converge on the same chain.

## Synchronization 
Nodes periodically exchange chain height information.


