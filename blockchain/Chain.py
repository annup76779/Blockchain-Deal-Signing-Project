import hashlib
import json
from . import Block
from datetime import datetime


def print_block(block):
    block_info = (
        f"Block Hash: {block.hash.hexdigest()}\n"
        f"Previous Hash: {block.previous_hash.hexdigest()}\n"
        f"Data: {block.data}\n"
        f"Nonce: {block.nonce}\n"
        f"Timestamp: {block.timestamp}\n"
        f"{'='*60}\n\n+"
    )
    print(block_info)


class Chain():
    def __init__(self, difficulty):
        self.difficulty = difficulty
        self.blocks = []
        self.pool = []
        self.create_origin_block()

    def proof_of_work(self, block):
        hash = hashlib.sha256()
        hash.update(str(block).encode('utf-8'))
        return block.hash.hexdigest() == hash.hexdigest() and int(hash.hexdigest(), 16) < 2**(256-self.difficulty) and block.previous_hash == self.blocks[-1].hash

    def add_to_chain(self, block):
        if self.proof_of_work(block):
            self.blocks.append(block)
            print_block(block)  # Append block data to the listbox

    def add_to_pool(self, document_hash, signature, public_key, signer_identity=None):
        data = {
            "document_hash": document_hash,
            "signature": signature,
            "public_key": public_key,
            "timestamp": datetime.utcnow().isoformat(),
            "signer_identity": signer_identity
        }
        self.pool.append(json.dumps(data))

    def create_origin_block(self):
        h = hashlib.sha256()
        h.update(''.encode('utf-8'))
        origin = Block("Origin", h)
        origin.mine(self.difficulty)
        self.blocks.append(origin)
        print_block(origin)  # Append origin block to the listbox

    def mine(self):
        while len(self.pool) > 0:
            data = self.pool.pop(0)  # Mine the first item in the pool
            block = Block(data, self.blocks[-1].hash)
            block.mine(self.difficulty)
            self.add_to_chain(block)
