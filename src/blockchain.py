# forked from https://github.com/dvf/blockchain
# Usage: Called from server.py
import hashlib
import json
import time
import threading
import logging
import uuid
import os
import requests
import umbral
import keygenreader as kgr
from umbral import encrypt, decrypt_reencrypted, generate_kfrags, reencrypt, CapsuleFrag, SecretKey, Signer

import requests
from flask import Flask, request

class ReEncryption():
    def __init__(self):
        self.key_filename = ''
        self.re_encrypt_private_key = None
        self.re_encrypt_public_key = None
        self.node_id = ''
        self.re_encrypt_signing_key = None
        self.re_encrypt_verify_key = None
        self.re_encrypt_signer = None
        
    def setup(self):
        key_dict = kgr.KeyFileReader(self.key_filename).get_keys()
        print(key_dict)
        self.re_encrypt_private_key = SecretKey.from_bytes(bytes.fromhex(key_dict['reencrypt_private_key']))
        self.re_encrypt_public_key = self.re_encrypt_private_key.public_key()
        self.node_id = str(bytes(self.re_encrypt_public_key).hex())
        self.re_encrypt_signing_key = SecretKey.from_bytes(bytes.fromhex(key_dict['reencrypt_signing_key']))
        self.re_encrypt_verify_key = self.re_encrypt_signing_key.public_key()
        self.re_encrypt_signer = Signer(self.re_encrypt_signing_key)
        
    def decrypt_message(self, txn):
        logging.info('Inside decrypt_message')
        txn_data = txn.data
        logging.info(txn_data)
        logging.info(type(txn_data))
        
        txn_data = json.loads(txn_data)
        logging.info(type(txn_data))
        logging.info(txn_data['capsule'])
        
        assert 'capsule' in txn_data
        assert 'ciphertext' in txn_data
        assert 'sender_pk' in txn_data
        assert 'sender_vk' in txn_data
        
        # Get kfrag from proxy
        # TODO: Change to cmd arg/config to get proxy reencrypt host
        kfrag_str = requests.get('http://localhost:5000/get/kfrag/' + txn.sender).text
        logging.info('kfrag_str')
        logging.info(kfrag_str)
        
        kfrag_hex = json.loads(kfrag_str)['kfrag']
        logging.info('kfrag_hex')
        logging.info(kfrag_hex)
        
        # Validate kfrag received
        cfrags = list()    
        # Assume singe kfrag             
        cfrag = reencrypt(capsule=umbral.Capsule.from_bytes(bytes.fromhex(txn_data['capsule'])), 
                          kfrag=umbral.VerifiedKeyFrag.from_verified_bytes(
                              bytes.fromhex(kfrag_hex)))
        cfrags.append(cfrag)
        logging.info('Captured cfrags')
            
        suspicious_cfrags = [CapsuleFrag.from_bytes(bytes(cfrag)) for cfrag in cfrags]
        logging.info('Got suspicious_cfrags')
        
        cfrags = [cfrag.verify(umbral.Capsule.from_bytes(bytes.fromhex(txn_data['capsule'])),
                    verifying_pk=umbral.PublicKey.from_bytes(bytes.fromhex(txn_data['sender_vk'])),
                    delegating_pk=umbral.PublicKey.from_bytes(bytes.fromhex(txn_data['sender_pk'])),
                    receiving_pk=self.re_encrypt_public_key,
                    )
        for cfrag in suspicious_cfrags]
        logging.info('Removed suspicious cfrags')
        
        # Decrypt the capsule
        cleartext = decrypt_reencrypted(receiving_sk=self.re_encrypt_private_key,
                        delegating_pk=umbral.PublicKey.from_bytes(bytes.fromhex(txn_data['sender_pk'])),
                        capsule=umbral.Capsule.from_bytes(bytes.fromhex(txn_data['capsule'])),
                        verified_cfrags=cfrags,
                        ciphertext=bytes.fromhex(txn_data['ciphertext']))
        
        logging.info('Decrypted the messsage. cleartext is ')
        logging.info(cleartext)
        return cleartext

    # TODO: Remove hardcoding
    def encrpyt_message(self, receiver_pk_hex):
        logging.info('Inside encrypt message')
        
        plaintext = b'Proxy Re-encryption is cool!'
        capsule, ciphertext = encrypt(self.re_encrypt_public_key, plaintext)
        logging.info('Called umbral encrypt')
        
        M, N = 1, 1 # the threshold and the total number of fragments
        kfrags = generate_kfrags(delegating_sk=self.re_encrypt_private_key, 
                                receiving_pk=umbral.PublicKey.from_bytes(
                                    bytes.fromhex(receiver_pk_hex)),
                                signer=self.re_encrypt_signer,
                                threshold=M,
                                shares=N)  
        
        logging.info('Called umbral kfrags')      
        logging.info(self.node_id)
        
        # give kfrag to proxy
        post_data = {}
        post_data['user'] = str(self.node_id)
        # Note: Only sending 1 kfrag, since we have only 1 proxy
        post_data['kfrag_hex'] = bytes(kfrags[0]).hex()
        requests.post('http://localhost:5000/receive/kfrag', 
                      json=json.dumps(post_data))
        
        logging.info('Completed post')
        
        return bytes(capsule).hex(), \
            ciphertext.hex(), \
            bytes(self.re_encrypt_public_key).hex(), \
            bytes(self.re_encrypt_verify_key).hex() 

class Transaction(object):
    def __init__(self, sender, recipient, data=""):
        # constraint: should exist in state
        self.sender = sender 
        # constraint: need not exist in state. 
        # Should exist in state if transaction is applied.
        self.recipient = recipient 
        # Represents data shared from sender to recipient. Can be None.
        self.data = data 
        
    def __str__(self) -> str:
        return "T(%s -> %s: %s)" % (self.sender, self.recipient, self.data)

    def encode(self) -> str:
        return self.__dict__.copy()

    @staticmethod
    def decode(data):
        return Transaction(data['sender'], data['recipient'], data['data'])

    def __lt__(self, other):
        if self.sender < other.sender: return True
        if self.sender > other.sender: return False
        if self.recipient < other.recipient: return True
        if self.recipient > other.recipient: return False
        return False
    
    def __eq__(self, other) -> bool:
        return self.sender == other.sender and \
          self.recipient == other.recipient and \
          self.data == other.data

class Block(object):
    def __init__(self, number, transactions, previous_hash, miner):
        # constraint: should be 1 larger than the previous block
        self.number = number 
        # constraint: list of transactions. Ordering matters. 
        # They will be applied sequentlally.
        self.transactions = transactions
        # constraint: Should match the previous mined block's hash 
        self.previous_hash = previous_hash
        # constraint: The node_identifier of the miner who mined this block 
        self.miner = miner 
        self.hash = self._hash()

    def _hash(self):
        return hashlib.sha256(
            str(self.number).encode('utf-8') +
            str([str(txn) for txn in self.transactions]).encode('utf-8') +
            str(self.previous_hash).encode('utf-8') +
            str(self.miner).encode('utf-8')
        ).hexdigest()

    def __str__(self) -> str:
        return "B(#%s, %s, %s, %s, %s)" % \
          (self.hash[:5], 
           self.number, 
           self.transactions, 
           self.previous_hash, 
           self.miner)
    
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
        self.data = {} # Dict from node id to data
        self.public_keys = {} # Dict from node id to public key
        self.id = ''
        self.dir = None
        self.re_encrypt = ReEncryption()
        
    def encode(self):
        dumped = {}
        for (k, v) in self.balance.items():
            dumped[k] = v
        return dumped

    # TODO
    def is_valid_txn(self, txn):
        return True

    # TODO: Not being used yet
    def save_data(self, data):
        random_id = str(uuid.uuid4())
        path = os.path.join(self.dir, random_id)

        with open(path, 'w') as f:
            f.write(data)
        
        print("Saving file data to: ", path)

    # Right now, this just decrypts the msg if it is the intended receipent
    def handle_txn_data(self, txn):
        # Extract data out of txn
        txn_data = txn.data
        txn_data = json.loads(txn_data)
        if not txn_data: 
            return
        
        # Can decrypt only if recipient is self
        if self.id == txn.recipient:
            decrypted_message = self.re_encrypt.decrypt_message(txn)

    def apply_txn(self, txn):
        self.handle_txn_data(txn)

    # returns a list of valid txns
    def validate_txns(self, txns):
        result = []
        
        for txn in txns:
            if self.is_valid_txn(txn):
                self.apply_txn(txn)
                result.append(txn)
                
        return result

    def apply_block(self, block):
        # No need to apply genesis block
        if block.number == 1: return

        # apply the block to the state
        valid_txns = self.validate_txns(block.transactions)
        assert len(valid_txns) == len(block.transactions) 
        for txn in block.transactions:
            self.apply_txn(txn)
        
        logging.info("Block (#%s) applied to state. %d transactions applied" % \
            (block.hash, len(block.transactions)))

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
        
        if current_miner == -1: 
            return min_node_id
        
        next_miner_id = min_node_id + \
            ((current_miner + 1 - min_node_id) % \
            (max_node_id - min_node_id + 1))
        
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

            # Create a new *valid* block with available transactions. Replace the arguments in the line below.
            valid_txns = self.state.validate_txns(self.current_transactions)
            previous_block = self.chain[-1] if len(self.chain) > 0 else None
            block = Block(previous_block.number + 1, valid_txns, previous_block.hash, miner)
             
        self.chain.append(block)
        
        self.current_transactions = [txn for txn in self.current_transactions if txn not in valid_txns]
        self.state.apply_block(block)

        logging.info("[MINER] constructed new block with %d transactions. Informing others about: #%s" % (len(block.transactions), block.hash[:5]))
        # broadcast the new block to all nodes.
        for node in self.nodes:
            if node == self.node_identifier: continue
            requests.post(f'http://localhost:{node}/inform/block', json=block.encode())

    def new_transaction(self, sender, recipient, data=""):
        """ Add this transaction to the transaction mempool. We will try
        to include this transaction in the next block until it succeeds.
        """
        # TODO: check that transaction is unique.
        logging.info('[DEBUG] Inside new transaction')
        new_txn = Transaction(sender, recipient, data)
        self.current_transactions.append(new_txn)
        
        print("Txns: ", self.current_transactions)
