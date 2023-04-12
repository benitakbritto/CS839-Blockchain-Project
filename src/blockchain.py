# forked from https://github.com/dvf/blockchain

import hashlib
import json
import time
import threading
import logging
import uuid
import rsa
import os
from cryptography.fernet import Fernet

import requests
from flask import Flask, request

class Transaction(object):
    def __init__(self, sender, recipient, amount, data=""):
        self.sender = sender # constraint: should exist in state
        self.recipient = recipient # constraint: need not exist in state. Should exist in state if transaction is applied.
        self.amount = amount # constraint: sender should have enough balance to send this amount
        self.data = data # Represents data shared from sender to recipient. Can be None.

    def __str__(self) -> str:
        return "T(%s -> %s: %s, %s)" % (self.sender, self.recipient, self.amount, self.data)

    def encode(self) -> str:
        return self.__dict__.copy()

    @staticmethod
    def decode(data):
        return Transaction(data['sender'], data['recipient'], data['amount'], data['data'])

    def __lt__(self, other):
        if self.sender < other.sender: return True
        if self.sender > other.sender: return False
        if self.recipient < other.recipient: return True
        if self.recipient > other.recipient: return False
        if self.amount < other.amount: return True
        return False
    
    def __eq__(self, other) -> bool:
        return self.sender == other.sender and self.recipient == other.recipient and self.amount == other.amount

class Block(object):
    def __init__(self, number, transactions, previous_hash, miner):
        self.number = number # constraint: should be 1 larger than the previous block
        self.transactions = transactions # constraint: list of transactions. Ordering matters. They will be applied sequentlally.
        self.previous_hash = previous_hash # constraint: Should match the previous mined block's hash
        self.miner = miner # constraint: The node_identifier of the miner who mined this block
        self.hash = self._hash()

    def _hash(self):
        return hashlib.sha256(
            str(self.number).encode('utf-8') +
            str([str(txn) for txn in self.transactions]).encode('utf-8') +
            str(self.previous_hash).encode('utf-8') +
            str(self.miner).encode('utf-8')
        ).hexdigest()

    def __str__(self) -> str:
        return "B(#%s, %s, %s, %s, %s)" % (self.hash[:5], self.number, self.transactions, self.previous_hash, self.miner)
    
    def encode(self):
        encoded = self.__dict__.copy()
        encoded['transactions'] = [t.encode() for t in self.transactions]
        return encoded
    
    @staticmethod
    def decode(data):
        txns = [Transaction.decode(t) for t in data['transactions']]
        return Block(data['number'], txns, data['previous_hash'], data['miner'])

class State(object):
    def __init__(self):
        # TODO: You might want to think how you will store balance per person.
        # You don't need to worry about persisting to disk. Storing in memory is fine.
        self.balance = {}
        self.history_log = {}
        self.data = {} # Dict from node id to data
        self.public_keys = {} # Dict from node id to public key
        self.symm_keys = {} # Dict from node id to symmetric key
        self.private_key = None
        self.id = None
        self.dir = None

    def encode(self):
        dumped = {}
        # TODO: Add all person -> balance pairs into `dumped`.
        for (k, v) in self.balance.items():
            dumped[k] = v
        return dumped

    def is_valid_txn(self, txn, curr_state):
        if txn.sender not in curr_state: return False
        if txn.amount > curr_state[txn.sender]: return False
        return True

    def save_data(self, data):
        random_id = str(uuid.uuid4())
        path = os.path.join(self.dir, random_id)

        with open(path, 'w') as f:
            f.write(data)
        print("Saving file data to: ", path)

    def handle_txn_data(self, txn, data, public_keys, symm_keys):
        # Extract data out of txn
        txn_data = txn.data
        txn_data = json.loads(txn_data)
        if not txn_data: return data, public_keys, symm_keys
        print("Public keys: ", public_keys)
        print("Symmetric keys: ", symm_keys)

        if txn.sender not in public_keys and 'pub_key' in txn_data:
            public_keys[txn.sender] = rsa.PublicKey.load_pkcs1(txn_data['pub_key'].encode('utf-8'))
            print("Step #1: Received public key from: ", txn.sender)
        
        # Can decrypt symmetric key only if recipient is self
        if self.id == int(txn.recipient) and 'symm_key' in txn_data:
            sender_symm_key = rsa.decrypt(bytes.fromhex(txn_data['symm_key']), self.private_key)
            symm_keys[txn.sender] = Fernet(sender_symm_key)
            print("Step #2: Received symmetric key from: ", txn.sender)
        
        print("Sender: {txn.sender}, Symmetric keys: ", symm_keys)
        # Can decrypt data only if recipient is self and symmetric key of sender is known
        if self.id == int(txn.recipient) and 'data' in txn_data and txn.sender in symm_keys:
            encrypted_data = txn_data['data']
            # Convert string to bytes
            encrypted_data = bytes(encrypted_data, 'utf-8')
            print("Step #3: Received encrypted data from: ", txn.sender)
            decoded_data = symm_keys[txn.sender].decrypt(encrypted_data).decode()
            self.save_data(decoded_data)

        return data, public_keys, symm_keys

    def apply_txn(self, txn, tmp_state, block_log={}, data={}, public_keys={}, symm_keys={}):
        print(txn)
        tmp_state[txn.sender] -= txn.amount
        if txn.recipient not in tmp_state:
            tmp_state[txn.recipient] = txn.amount
        else:
            tmp_state[txn.recipient] += txn.amount

        if txn.sender not in block_log: block_log[txn.sender] = -txn.amount
        else: block_log[txn.sender] -= txn.amount
        if txn.recipient not in block_log: block_log[txn.recipient] = txn.amount
        else: block_log[txn.recipient] += txn.amount

        data, public_keys, symm_keys = self.handle_txn_data(txn, data, public_keys, symm_keys)
        return tmp_state, block_log, data, public_keys, symm_keys

    def validate_txns(self, txns):
        result = []
        # TODO: returns a list of valid transactions.
        # You receive a list of transactions, and you try applying them to the state.
        # If a transaction can be applied, add it to result. (should be included)
        tmp_state = self.balance.copy()
        data = self.data.copy()
        pk = self.public_keys.copy()
        sk = self.symm_keys.copy()
        for txn in txns:
            if self.is_valid_txn(txn, tmp_state):
                tmp_state, _, _, pk, sk = self.apply_txn(txn, tmp_state, {}, data, pk, sk)
                print("Public keys modified: ", pk)
                result.append(txn)

        print("Initial transactions: ", txns)
        print("Valid transactions: ", result)
        print("Initial state: ", self.encode())
        print("Final state: ", tmp_state)
        print("Result len: %d" % len(result))
        print("Data: ", data)
        print("Public keys: ", pk)
        print("Symmetric keys: ", sk)
        return result

    def apply_block(self, block):
        # No need to apply genesis block
        if block.number == 1: return

        # TODO: apply the block to the state.
        valid_txns = self.validate_txns(block.transactions)
        assert len(valid_txns) == len(block.transactions) # TODO: make sure if this is correct

        block_log = {}
        for txn in block.transactions:
            self.balance, block_log, self.data, self.public_keys, self.symm_keys = self.apply_txn(txn, self.balance, block_log, self.data, self.public_keys, self.symm_keys)
        
        self.history_log[block.number] = block_log

        logging.info("Block (#%s) applied to state. %d transactions applied" % (block.hash, len(block.transactions)))
    
    def history(self, account):
        # TODO: return a list of (blockNumber, value changes) that this account went through
        
        # Iterate over blocks, and check if this account was involved in any transaction.
        # Add up all the value changes and get the final change for the block
        history = []

        for (block_num, block_log) in self.history_log.items():
            if account in block_log:
                history.append([block_num, block_log[account]])
        print(history)

        return history

class Blockchain(object):
    def __init__(self):
        self.nodes = []
        self.node_identifier = 0
        self.block_mine_time = 5

        # in memory datastructures.
        self.current_transactions = [] # A list of `Transaction`
        self.chain = [] # A list of `Block`
        self.state = State()

    def get_next_miner(self, current_miner):
        max_node_id, min_node_id = max(self.nodes), min(self.nodes)
        if current_miner == -1: return min_node_id
        next_miner_id = min_node_id + ((current_miner + 1 - min_node_id) % (max_node_id - min_node_id + 1))
        return next_miner_id

    def is_new_block_valid(self, block, received_blockhash):
        """
        Determine if I should accept a new block.
        Does it pass all semantic checks? Search for "constraint" in this file.

        :param block: A new proposed block
        :return: True if valid, False if not
        """
        # TODO: check if received block is valid
        # 1. Hash should match content
        # 2. Previous hash should match previous block
        # 3. Transactions should be valid (all apply to block)
        # 4. Block number should be one higher than previous block
        # 5. miner should be correct (next RR)
        previous_block = None
        if len(self.chain) > 0: previous_block = self.chain[-1]
        current_miner = previous_block.miner if previous_block else -1
        next_miner = self.get_next_miner(current_miner)
        valid_txns = self.state.validate_txns(block.transactions)

        #1
        if (received_blockhash != block.hash) or (received_blockhash != block._hash()):
            return False
        
        #2
        if len(self.chain) > 0 and block.previous_hash != previous_block.hash:
            return False
        if len(self.chain) == 0 and block.previous_hash != '0xfeedcafe':
            return False
        
        #3
        if len(valid_txns) != len(block.transactions):
            return False

        #4
        if len(self.chain) > 0 and (block.number != previous_block.number + 1):
            return False
        if len(self.chain) == 0 and (block.number != 1):
            return False
       
        #5
        if block.miner != next_miner:
            return False


        return True

    def trigger_new_block_mine(self, genesis=False):
        thread = threading.Thread(target=self.__mine_new_block_in_thread, args=(genesis,))
        thread.start()

    def __mine_new_block_in_thread(self, genesis=False):
        """
        Create a new Block in the Blockchain

        :return: New Block
        """
        logging.info("[MINER] waiting for new transactions before mining new block...")
        time.sleep(self.block_mine_time) # Wait for new transactions to come in
        miner = self.node_identifier

        valid_txns = []
        if genesis:
            block = Block(1, [], '0xfeedcafe', miner)
        else:
            self.current_transactions.sort()

            # TODO: create a new *valid* block with available transactions. Replace the arguments in the line below.
            valid_txns = self.state.validate_txns(self.current_transactions)
            previous_block = self.chain[-1] if len(self.chain) > 0 else None
            # My todo: check if previous block is present or if chain is empty
            block = Block(previous_block.number + 1, valid_txns, previous_block.hash, miner)
             
        # TODO: make changes to in-memory data structures to reflect the new block. Check Blockchain.__init__ method for in-memory datastructures
        self.chain.append(block)
        if genesis:
            # TODO: at time of genesis, change state to have '5001': 10000 (person 5001 has 10000)
            self.state.balance['5001'] = 10000
            self.state.history_log[1] = {'5001': 10000}
            print("Initializing state and history in-memory data structures")
        
        self.current_transactions = [txn for txn in self.current_transactions if txn not in valid_txns]
        self.state.apply_block(block)

        logging.info("[MINER] constructed new block with %d transactions. Informing others about: #%s" % (len(block.transactions), block.hash[:5]))
        # broadcast the new block to all nodes.
        for node in self.nodes:
            if node == self.node_identifier: continue
            requests.post(f'http://localhost:{node}/inform/block', json=block.encode())

    def new_transaction(self, sender, recipient, amount, data=""):
        """ Add this transaction to the transaction mempool. We will try
        to include this transaction in the next block until it succeeds.
        """
        # TODO: check that transaction is unique.
        new_txn = Transaction(sender, recipient, amount, data)
        self.current_transactions.append(new_txn)
        
        print("Txns: ", self.current_transactions)
