# forked from https://github.com/dvf/blockchain
# Usage: Called from server.py
from __future__ import annotations
import hashlib
import json

import time
import threading
import logging
import requests
from pyring.one_time import PublicKey
from pyring.ge import *

from constants import TxnType
from reencryption import ReEncryption
from anonymization import Anonymization
from wallet import Wallet
from txn import Transaction
from block import Block
from state import State

class Blockchain(object):
    def __init__(self):
        self.nodes = []
        self.node_identifier = 0
        self.block_mine_time = 5

        # in memory datastructures.
        self.current_transactions = []  # A list of `Transaction`
        self.chain = []  # A list of `Block`
        self.state = State()

    def get_next_miner(self, current_miner):
        max_node_id, min_node_id = max(self.nodes), min(self.nodes)

        if current_miner == -1:
            return min_node_id

        next_miner_id = min_node_id + (
            (current_miner + 1 - min_node_id) % (max_node_id - min_node_id + 1)
        )

        return next_miner_id

    def is_new_block_valid(self, block, received_blockhash):
        """
        Determine if I should accept a new block.
        Does it pass all semantic checks? Search for "constraint" in this file.

        :param block: A new proposed block
        :return: True if valid, False if not
        """
        # Checks if received block is valid
        # 1. Hash should match content
        # 2. Previous hash should match previous block
        # 3. Transactions should be valid (all apply to block)
        # 4. Block number should be one higher than previous block
        # 5. miner should be correct (next RR)
        previous_block = None

        if len(self.chain) > 0:
            previous_block = self.chain[-1]
        current_miner = previous_block.miner if previous_block else -1
        next_miner = self.get_next_miner(current_miner)
        valid_txns = self.state.validate_txns(block.transactions)

        # 1
        if (received_blockhash != block.hash) or (received_blockhash != block._hash()):
            return False

        # 2
        if len(self.chain) > 0 and block.previous_hash != previous_block.hash:
            return False
        if len(self.chain) == 0 and block.previous_hash != "0xfeedcafe":
            return False

        # 3
        if len(valid_txns) != len(block.transactions):
            return False

        # 4
        if len(self.chain) > 0 and (block.number != previous_block.number + 1):
            return False
        if len(self.chain) == 0 and (block.number != 1):
            return False

        # 5
        if block.miner != next_miner:
            return False

        return True

    def trigger_new_block_mine(self, genesis=False):
        thread = threading.Thread(
            target=self.__mine_new_block_in_thread, args=(genesis,)
        )
        thread.start()

    def __mine_new_block_in_thread(self, genesis=False):
        """
        Create a new Block in the Blockchain

        :return: New Block
        """
        # logging.info("[MINER] waiting for new transactions before mining new block...")
        time.sleep(self.block_mine_time)  # Wait for new transactions to come in
        miner = self.node_identifier

        # Form a block of valid txns
        valid_txns = []
        if genesis:
            block = Block(1, [], "0xfeedcafe", miner)
        else:
            self.current_transactions.sort()

            # Create a new *valid* block with available transactions. Replace the arguments in the line below.
            valid_txns = self.state.validate_txns(self.current_transactions)
            previous_block = self.chain[-1] if len(self.chain) > 0 else None
            block = Block(
                previous_block.number + 1, valid_txns, previous_block.hash, miner
            )

        # Pending txns
        self.current_transactions = [
            txn for txn in self.current_transactions if txn not in valid_txns
        ]

        # Update blockchain state
        self.chain.append(block)
        self.state.apply_block(block, self.chain)

        # logging.info(
        #     "[MINER] constructed new block with %d transactions. Informing others about: #%s"
        #     % (len(block.transactions), block.hash[:5])
        # )
        # broadcast the new block to all nodes.
        for node in self.nodes:
            if node == self.node_identifier:
                continue
            requests.post(f"http://localhost:{node}/inform/block", json=block.encode())

    def new_transaction(self, sender: str, recipient: str, data: str):
        """Add this transaction to the transaction mempool. We will try
        to include this transaction in the next block until it succeeds.
        """
        new_txn = Transaction(recipient, data)

        signature_str = self.state.anon.get_ring_signature(
            self.state.wallet.public_key_addr, self.state.wallet.private_key_addr, new_txn.__str__()
        )
        new_txn.set_signature(signature_str)
        self.current_transactions.append(new_txn)

        logging.info(f"!!! New transaction received: {new_txn} !!!")

        return new_txn.id
