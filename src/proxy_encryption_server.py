# Usage: python3 proxy-reencryption.py -p <port num>

from flask import Flask, request, jsonify
import json
from argparse import ArgumentParser
import logging
import umbral

app = Flask(__name__)


# In-mem state
class Proxy_State:
    def __init__(self):
        # key: concat(sender_pk, receiver_pk)
        # value: single kfrag in hex
        self.kfrag_dict = {}

    def form_key(self, sender_pk: str, receiver_pk: str) -> str:
        return sender_pk + "_" + receiver_pk

    def update_state(
        self, sender_pk_hex: str, receiver_pk_hex: str, kfrag_hex: str, capsule_hex: str
    ) -> str:
        _key = self.form_key(sender_pk_hex, receiver_pk_hex)

        capsule_obj = umbral.Capsule.from_bytes(bytes.fromhex(capsule_hex))
        kfrag_obj = umbral.VerifiedKeyFrag.from_verified_bytes(bytes.fromhex(kfrag_hex))

        self.kfrag_dict[_key] = umbral.reencrypt(capsule=capsule_obj, kfrag=kfrag_obj)

    def get_state(self, sender_pk: str, receiver_pk: str) -> str:
        _key = self.form_key(sender_pk, receiver_pk)

        if _key not in self.kfrag_dict.keys():
            return None

        return bytes(self.kfrag_dict[_key]).hex()


@app.route("/post/kfrag", methods=["POST"])
def post_kfrag():
    # Extract info from payload
    values = json.loads(request.get_json())
    required = ["sender_pk", "receiver_pk", "kfrag_hex", "capsule"]
    if not all(req in values for req in required):
        return "Missing values", 400

    # Update state
    sender_pk = values["sender_pk"]
    receiver_pk = values["receiver_pk"]
    kfrag_hex = values["kfrag_hex"]
    capsule = values["capsule"]
    proxy_state.update_state(sender_pk, receiver_pk, kfrag_hex, capsule)

    return "OK", 201


@app.route("/get/kfrag/<sender_pk>/<receiver_pk>", methods=["GET"])
def get_kfrag(sender_pk, receiver_pk):
    kfrag_hex = proxy_state.get_state(sender_pk, receiver_pk)

    if kfrag_hex is None:
        return "Missing key", 400

    response = {"kfrag_hex": kfrag_hex}

    return jsonify(response), 200


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.INFO)

    parser = ArgumentParser()
    parser.add_argument(
        "-p", "--port", default=5000, type=int, help="port to listen on"
    )

    args = parser.parse_args()
    port = args.port

    proxy_state = Proxy_State()
    app.run(host="0.0.0.0", port=port)
