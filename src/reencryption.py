import umbral
import requests
import json
import logging
from umbral import (
    encrypt,
    decrypt_reencrypted,
    CapsuleFrag,
)

class ReEncryption:
    def __init__(self, proxy_url):
        self.proxy_url = proxy_url

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
            f"{self.proxy_url}post/kfrag", json=json.dumps(data_dict)
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
            f"{self.proxy_url}get/kfrag/{txn_data['sender_r_pk']}/{bytes(receiver_pk).hex()}"
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

