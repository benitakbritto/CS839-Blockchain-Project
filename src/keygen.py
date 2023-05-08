# Usage: python3 <python filename> -f <output file name>
from umbral import SecretKey, Signer
from pyring.one_time import PrivateKey, PublicKey
from pyring.ge import *
from pyring.sc25519 import Scalar
import json


# Generates the required private keys and returns as json
def generate_keys():
    data = {}
    reencrypt_private_key = SecretKey.random()
    reencrypt_signing_key = SecretKey.random()
    private_key_addr = PrivateKey.generate()

    data["reencrypt_private_key"] = reencrypt_private_key.to_secret_bytes().hex()
    data["reencrypt_public_key"] = bytes(reencrypt_private_key.public_key()).hex()
    data["reencrypt_signing_key"] = reencrypt_signing_key.to_secret_bytes().hex()
    
    data["private_key_addr"] = bytes(private_key_addr.scalar.data).hex()
    data["public_key_addr"] = private_key_addr.public_key().point.as_bytes().hex()
    return json.dumps(data)


def write_to_file(path, json_str):
    with open(path, "w") as outfile:
        outfile.write(json_str)


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument(
        "-f",
        "--filename",
        type=str,
        help="file name to store generated keys",
        required=True,
    )

    args = parser.parse_args()

    keys_str = generate_keys()
    write_to_file(args.filename, keys_str)
