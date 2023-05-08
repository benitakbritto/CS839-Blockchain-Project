# forked from https://github.com/dvf/blockchain
# Usage: Called from server.py
from __future__ import annotations
import hashlib
import json
from random import randint, random
import time
import threading
import logging
import uuid
import os
from xmlrpc.client import boolean
import requests
from pyring.one_time import PrivateKey, PublicKey, ring_sign, ring_verify
from pyring.ge import *
from pyring.sc25519 import Scalar
from pyring.serialize import import_pem, export_pem
import umbral
import keygenreader as kgr
from umbral import (
    encrypt,
    decrypt_reencrypted,
    generate_kfrags,
    reencrypt,
    CapsuleFrag,
    SecretKey,
    Signer,
)
from enum import Enum

import requests
from flask import Flask, request
import hashlib


class Wallet:
    def __init__(self):
        self.re_encrypt_private_key = None
        self.re_encrypt_public_key = None
        self.re_encrypt_signing_key = None
        self.re_encrypt_verify_key = None
        self.re_encrypt_signer = None

        self.public_key_addr = None
        self.private_key_addr = None

    def setup(self, file_name):
        """@brief: init keys by reading the file"""
        key_dict = kgr.KeyFileReader(file_name).get_keys()
        self.re_encrypt_private_key = SecretKey.from_bytes(
            bytes.fromhex(key_dict["reencrypt_private_key"])
        )
        self.re_encrypt_public_key = self.re_encrypt_private_key.public_key()

        self.re_encrypt_signing_key = SecretKey.from_bytes(
            bytes.fromhex(key_dict["reencrypt_signing_key"])
        )
        self.re_encrypt_verify_key = self.re_encrypt_signing_key.public_key()
        self.re_encrypt_signer = Signer(self.re_encrypt_signing_key)

        self.private_key_addr = PrivateKey(
            Scalar(bytes.fromhex(key_dict["private_key_addr"]))
        )  # b
        self.public_key_addr = self.private_key_addr.public_key()  # B = b * G


class TxnType(Enum):
    UPLOAD = 1
    SHARE = 2
    INVALID = -1


class Anonymization:
    def __init__(self):
        # Ideally this should belong to a random number
        self.num_keys = 10

    def get_ring_signature(self, pk: PublicKey, sk: PrivateKey, message: str) -> str:
        # decide actual sender's position in the ring
        signer_index = randint(0, self.num_keys - 1)

        # get the public keys to form the ring
        public_keys = []
        for key_index in range(self.num_keys):
            if key_index == signer_index:
                public_key = pk
                signer_key = sk
            else:
                # For now, we are generating random (pk, sk) pairs
                # Ideally, we would know a few pks and only generate sks
                private_key = PrivateKey.generate()
                public_key = private_key.public_key()

            public_keys.append(public_key.point)

        signature = ring_sign(
            bytes(message, 'utf-8'), public_keys, signer_key.scalar, signer_index
        )

        # Serialize signature
        return export_pem(signature)

    def is_signature_valid(self, signature: str, message: str) -> bool:
        # deserialize
        signature = import_pem(signature)

        # perform checks
        assert len(signature.c) == self.num_keys
        assert len(signature.r) == self.num_keys
        assert len(signature.public_keys) == self.num_keys

        return ring_verify(bytes(message, 'utf-8'), signature)

    # TODO
    def anonymize_txn_ref(self, txn_ref_id: str):
        pass

    # TODO
    def anonymize_sender_reencrypt_pk(self, pk: str):
        pass

    # TODO
    def anonymize_sender_reencrypt_vk(self, vk: str):
        pass

    def anonymize_receiver(self, receiver_addr: str):
        # generate shared randomness
        r = PrivateKey.generate()
        R = r.public_key()

        # Convert point bytes to Public Key
        B = PublicKey(Point(bytes.fromhex(receiver_addr)))
        rB = PublicKey(r.scalar * B.point)

        shared_randomness = R.point.as_bytes().hex()

        stealth_address = rB.point.as_bytes().hex()
        stealth_address = (
            hashlib.sha256(bytes.fromhex(stealth_address)).hexdigest().encode().hex()
        )

        return shared_randomness, stealth_address


class ReEncryption:
    def __init__(self):
        self.proxy_base_url = "http://localhost:5000/"

    def pack_data_for_post(
        self,
        sender_pk: umbral.PublicKey,
        receive_pk: umbral.PublicKey,
        kfrag: umbral.VerifiedKeyFrag,
        capsule_hex: str,
    ) -> dict[str, str]:
        data_dict = {}
        data_dict["sender_pk"] = bytes(sender_pk).hex()
        data_dict["receiver_pk"] = bytes(receive_pk).hex()
        data_dict["kfrag_hex"] = bytes(kfrag).hex()
        data_dict["capsule"] = capsule_hex

        return data_dict

    def send_reencryption_key_to_proxy(
        self,
        sender_pk: umbral.PublicKey,
        sender_sk: umbral.SecretKey,
        receiver_pk_hex: str,
        sender_signer: umbral.Signer,
        capsule_hex: str,
    ):
        receiver_pk = umbral.PublicKey.from_bytes(bytes.fromhex(receiver_pk_hex))
        kfrags = self.generate_re_encrypt_key(sender_sk, receiver_pk, sender_signer)

        data_dict = self.pack_data_for_post(
            sender_pk, receiver_pk, kfrags[0], capsule_hex
        )
        r = requests.post(
            f"{self.proxy_base_url}post/kfrag", json=json.dumps(data_dict)
        )
        assert r.status_code == 201

    def generate_re_encrypt_key(
        self,
        sender_sk: umbral.SecretKey,
        receiver_pk: umbral.PublicKey,
        sender_signer: umbral.Signer,
    ):
        # the threshold and the total number of fragments
        M, N = 1, 1
        kfrags = umbral.generate_kfrags(
            delegating_sk=sender_sk,
            receiving_pk=receiver_pk,
            signer=sender_signer,
            threshold=M,
            shares=N,
        )

        return kfrags

    def get_kfrag_from_proxy(
        self, txn_data: dict[str, str], receiver_pk: umbral.PublicKey
    ) -> str:
        r = requests.get(
            f"{self.proxy_base_url}get/kfrag/{txn_data['sender_r_pk']}/{bytes(receiver_pk).hex()}"
        )
        assert r.status_code == 200

        return json.loads(r.text)["kfrag_hex"]

    def verify_cfrag_received_from_proxy(
        self, txn_data: dict[str, str], cfrags: list[str], receiver_pk: umbral.PublicKey
    ) -> list[umbral.VerifiedCapsuleFrag]:
        suspicious_cfrags = [
            CapsuleFrag.from_bytes(bytes.fromhex(cfrag)) for cfrag in cfrags
        ]
        cfrags = [
            cfrag.verify(
                umbral.Capsule.from_bytes(bytes.fromhex(txn_data["capsule"])),
                verifying_pk=umbral.PublicKey.from_bytes(
                    bytes.fromhex(txn_data["verify_r_pk"])
                ),
                delegating_pk=umbral.PublicKey.from_bytes(
                    bytes.fromhex(txn_data["sender_r_pk"])
                ),
                receiving_pk=receiver_pk,
            )
            for cfrag in suspicious_cfrags
        ]

        return cfrags

    def get_cleartext(
        self,
        txn_data: dict[str, str],
        cfrags: list[umbral.VerifiedCapsuleFrag],
        receiver_sk: umbral.SecretKey,
    ) -> bytes:
        return decrypt_reencrypted(
            receiving_sk=receiver_sk,
            delegating_pk=umbral.PublicKey.from_bytes(
                bytes.fromhex(txn_data["sender_r_pk"])
            ),
            capsule=umbral.Capsule.from_bytes(bytes.fromhex(txn_data["capsule"])),
            verified_cfrags=cfrags,
            ciphertext=bytes.fromhex(txn_data["ciphertext"]),
        )

    def decrypt_message(
        self,
        txn_data: dict[str, str],
        receiver_pk: umbral.PublicKey,
        receiver_sk: umbral.SecretKey,
    ):
        # Contact proxy to get cfrag
        kfrag_hex = self.get_kfrag_from_proxy(txn_data, receiver_pk)
        cfrags = list()
        cfrags.append(kfrag_hex)

        # Verify cfrags received from proxy, as proxy is semi-trusted
        cfrags = self.verify_cfrag_received_from_proxy(txn_data, cfrags, receiver_pk)

        # Decrypt
        cleartext = self.get_cleartext(txn_data, cfrags, receiver_sk)
        logging.info(f"!!! Decrpted message content: {cleartext} !!!")

        return cleartext

    def encrypt_message(
        self, sender_pk: umbral.PublicKey, plaintext: str
    ) -> list[str, str]:
        capsule, ciphertext = encrypt(sender_pk, plaintext)

        return (bytes(capsule).hex(), ciphertext.hex())


class Transaction(object):
    def __init__(self, recipient, data, id=None, signature=None):
        self.recipient = recipient
        if id is None:
            self.id = uuid.uuid4().hex
        else:
            self.id = id
        # Represents data shared from sender to recipient. Can be None.
        self.data = data
        if signature is not None:
            self.signature = signature

    def set_signature(self, signature_str: str):
        self.signature = signature_str

    def __str__(self) -> str:
        return "T(%s->[%s: %s])" % (
            self.id,
            self.recipient,
            self.data,
        )

    def encode(self) -> str:
        return self.__dict__.copy()

    @staticmethod
    def decode(data):
        return Transaction(
            data["recipient"], data["data"], data["id"], data["signature"]
        )

    def __lt__(self, other):
        if self.recipient < other.recipient:
            return True
        if self.recipient > other.recipient:
            return False
        return False

    def __eq__(self, other) -> bool:
        return (
            self.recipient == other.recipient
            and self.data == other.data
            and self.id == other.id
            and self.signature == other.signature
        )


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
            str(self.number).encode("utf-8")
            + str([str(txn) for txn in self.transactions]).encode("utf-8")
            + str(self.previous_hash).encode("utf-8")
            + str(self.miner).encode("utf-8")
        ).hexdigest()

    def __str__(self) -> str:
        return "B(#%s, %s, %s, %s, %s)" % (
            self.hash[:5],
            self.number,
            self.transactions,
            self.previous_hash,
            self.miner,
        )

    def encode(self):
        encoded = self.__dict__.copy()
        encoded["transactions"] = [t.encode() for t in self.transactions]
        return encoded

    @staticmethod
    def decode(data):
        txns = [Transaction.decode(t) for t in data["transactions"]]
        return Block(data["number"], txns, data["previous_hash"], data["miner"])


class State(object):
    def __init__(self):
        self.data = {}  # Dict from node id to data
        self.public_keys = {}  # Dict from node id to public key
        # TODO: This should hold pyring pk
        self.id = ""
        self.dir = None
        self.re_encrypt = ReEncryption()
        self.anon = Anonymization()
        self.wallet = Wallet()

    def encode(self):
        dumped = {}
        for k, v in self.balance.items():
            dumped[k] = v
        return dumped

    def is_valid_txn(self, txn):
        '''Validate the txn type and ring signature'''
        txn_type = self.get_txn_type_from_data_field(json.loads(txn.data))
        txn_signature = txn.signature
        
        return True if (txn_type is not TxnType.INVALID and self.anon.is_signature_valid(txn_signature, txn.__str__())) else False

    # Get data from txn data field with particular id on chain
    # TODO: Refactor
    def get_txn_ref_data(self, txn_id, chain):
        for block in chain:
            for txn in block.transactions:
                if txn.id == txn_id:
                    return json.loads(txn.data)
        logging.warn("Could not find txn with id: %s" % txn_id)
        return None

    def get_capsule_from_txn_id(self, txn_id, chain):
        txn_data = self.get_txn_ref_data(txn_id, chain)
        return txn_data["capsule"]

    def get_txn_type_from_data_field(self, txn_data: dict[str, str]) -> int:
        upload_txn_required = ["capsule", "ciphertext"]
        share_txn_required = ["data_txn_ref", "sender_r_pk", "verify_r_pk"]

        if all(k in txn_data for k in upload_txn_required):
            return TxnType.UPLOAD

        if all(k in txn_data for k in share_txn_required):
            return TxnType.SHARE

        return TxnType.INVALID

    def match_stealth_address(self, stealth_address, shared_randomness) -> bool:
        '''Match stealth address by checking if rB (transmitted by sender) == bR (computed by receiver)'''
        hashed_rB = stealth_address
        R = PublicKey(Point(bytes.fromhex(shared_randomness)))
        bR = PublicKey(self.wallet.private_key_addr.scalar * R.point)
        hashed_bR = hashlib.sha256(bR.point.as_bytes()).hexdigest().encode().hex()
        return hashed_rB == hashed_bR

    def apply_share_txn(self, txn, chain):
        # Get txn ref
        txn_data = json.loads(txn.data)
        txn_ref = txn_data["data_txn_ref"]
        ref_txn_data = self.get_txn_ref_data(txn_ref, chain)

        # Return if txn ref not found
        if not ref_txn_data:
            return


        # Extract info from txn ref
        txn_data["capsule"] = ref_txn_data["capsule"]
        txn_data["ciphertext"] = ref_txn_data["ciphertext"]

        # Can decrypt only if recipient is self
        # Match stealth address by recomputing it using receiver private key and shared randomness
        if self.match_stealth_address(
            txn.recipient, txn_data["shared_randomness"]
        ):
            logging.info("!!! I am the recipient !!!")
            decrypted_message = self.re_encrypt.decrypt_message(
                txn_data,
                self.wallet.re_encrypt_public_key,
                self.wallet.re_encrypt_private_key,
            )
        else:
            logging.info("!!! I am not the recipient !!!")

    def apply_txn_data(self, txn, chain):
        # Extract data field from txn
        txn_data = json.loads(txn.data)

        if not txn_data:
            return

        txn_type = self.get_txn_type_from_data_field(txn_data)
        if txn_type == TxnType.UPLOAD:
            return
        elif txn_type == TxnType.SHARE:
            self.apply_share_txn(txn, chain)
        else:
            return

    def apply_txn(self, txn, chain):
        self.apply_txn_data(txn, chain)

    def validate_txns(self, txns):
        """returns a list of valid txns"""
        result = [txn for txn in txns if self.is_valid_txn(txn)]
        return result

    def apply_block(self, block, chain):
        # No need to apply genesis block
        if block.number == 1:
            return

        # apply the block to the state
        valid_txns = self.validate_txns(block.transactions)
        assert len(valid_txns) == len(block.transactions)

        for txn in block.transactions:
            self.apply_txn(txn, chain)

        # logging.info(
        #     "Block (#%s) applied to state. %d transactions applied"
        #     % (block.hash, len(block.transactions))
        # )


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
