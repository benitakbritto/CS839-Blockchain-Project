import keygenreader as kgr
from umbral import SecretKey, Signer
from pyring.one_time import PrivateKey
from pyring.sc25519 import Scalar

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
