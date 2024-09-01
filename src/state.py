import logging
import json
import hashlib

from constants import TxnType
from constants import TxnType
from reencryption import ReEncryption
from anonymization import Anonymization
from wallet import Wallet
from pyring.one_time import PublicKey

class State(object):
    def __init__(self):
        self.data = {}  # Dict from node id to data
        self.public_keys = {}  # Dict from node id to public key
        # TODO: This should hold pyring pk
        self.id = ""
        self.dir = None
        self.re_encrypt = ReEncryption(proxy_url="http://localhost:6000")
        self.anon = Anonymization(num_keys=10)
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
