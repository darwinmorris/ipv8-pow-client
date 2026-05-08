import asyncio
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8_service import IPv8
import hashlib
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.peer import Peer
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile


NONCE_FILE = "nonce.txt"
EMAIL = "D.B.Morris-1@student.tudelft.nl"
GITHUB_URL = "https://github.com/darwinmorris/ipv8-pow-client"
KEY_FILE = "lab1_key.pem"

COMMUNITY_ID = bytes.fromhex(
    "2c1cc6e35ff484f99ebdfb6108477783c0102881"
)

SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
)



def has_leading_zeros(digest: bytes) -> bool:
    return (
        digest[0] == 0
        and digest[1] == 0
        and digest[2] == 0
        and digest[3] < 16 
    )

from ipv8.messaging.lazy_payload import VariablePayload, vp_compile


@vp_compile
class SubmissionPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]


@vp_compile
class ResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]

def find_nonce(email: str, github_url: str) -> int:
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    base = hashlib.sha256(prefix)
    nonce = 0

    while nonce <= 2**63 - 1:
        h = base.copy()
        h.update(nonce.to_bytes(8, byteorder="big", signed=True))
        digest = h.digest()

        if has_leading_zeros(digest):
            with open(NONCE_FILE, "w") as f:
                f.write(str(nonce))
            return nonce
        
        if nonce % 1000000 == 0:
            print(f"checked till {nonce}")
        
        nonce += 1

class HetCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.done = asyncio.Event()
        self.add_message_handler(ResponsePayload, self.on_response)

    def find_peer(self):
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                return peer
        
        return None
    
    def register_attempt(self, email: str, github_url: str, nonce: int) -> bool:
        server = self.find_peer()
        
        if server is None:
            return False

        print("Found correct peer, sending submission")

        self.ez_send(server, SubmissionPayload(email, github_url, nonce))
        return True

    
    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer: Peer, payload: ResponsePayload) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            print("Ignore")
            return
        print(payload.success)
        print(payload.message)
        self.done.set()
    



async def start_ipv8() -> None:
    print("Proof of work")
    try:
        with open(NONCE_FILE) as f:
            nonce = int(f.read().strip())

        print(f"Loaded nonce: {nonce}")

    except FileNotFoundError:
        print("Mining proof of work...")
        nonce = find_nonce(EMAIL, GITHUB_URL)

        with open(NONCE_FILE, "w") as f:
            f.write(str(nonce))
        

    print(f"Found nonce: {nonce}")

    builder = ConfigBuilder()
    builder.clear_keys()
    builder.clear_overlays()

    builder.add_key(
        "hetpeer",
        "curve25519",
        KEY_FILE
    )

    builder.add_overlay("HetCommunity", "hetpeer",
                            [WalkerDefinition(Strategy.RandomWalk,
                                              10, {"timeout": 3.0})],
                            default_bootstrap_defs, {}, [])

    ipv8 = IPv8(builder.finalize(),
                   extra_communities={"HetCommunity": HetCommunity})
    await ipv8.start()

    community = ipv8.get_overlay(HetCommunity)

    print("IPv8 started, searching for peer")
    try:
        while not community.register_attempt(EMAIL, GITHUB_URL, nonce):
            print(f"peers: {community.get_peers()}")
            await asyncio.sleep(2)
        
        await community.done.wait()


    finally:
        await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(start_ipv8())