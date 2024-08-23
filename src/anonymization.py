from pyring.one_time import PrivateKey, PublicKey, ring_sign, ring_verify
from pyring.ge import *
from pyring.serialize import import_pem, export_pem

from random import randint, random


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
