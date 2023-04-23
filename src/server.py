# Usage: python3 server.py -p 5001 -n 5001 5002 5003 -f 5001.json
from flask import Flask, request, jsonify
import logging
import blockchain as bc
import os
import json

import hashlib
from pyring.one_time import PrivateKey, PublicKey
from pyring.ge import *

# Instantiate the Node
app = Flask(__name__)

# Instantiate the Blockchain
blockchain = bc.Blockchain()


@app.route("/inform/block", methods=["POST"])
def new_block_received():
    values = request.get_json()
    logging.info("Received: " + str(values))

    # Check that the required fields are in the POST'ed data
    required = ["number", "transactions", "miner", "previous_hash", "hash"]
    if not all(k in values for k in required):
        logging.warning("[RPC: inform/block] Missing values")
        return "Missing values", 400

    block = bc.Block.decode(values)
    valid = blockchain.is_new_block_valid(block, values["hash"])

    if not valid:
        logging.warning("[RPC: inform/block] Invalid block")
        return "Invalid block", 400

    # Modify in-memory data structures to reflect the new block
    blockchain.chain.append(block)
    blockchain.state.apply_block(block, blockchain.chain)

    # if I am responsible for next block, start mining it (trigger_new_block_mine).
    max_node_id, min_node_id = max(blockchain.nodes), min(blockchain.nodes)
    next_miner_id = min_node_id + (
        (block.miner + 1 - min_node_id) % (max_node_id - min_node_id + 1)
    )
    if next_miner_id == blockchain.node_identifier:
        blockchain.trigger_new_block_mine()

    return "OK", 201


def file_data(filepath):
    if not os.path.isfile(filepath):
        data = "Proxy Re-encryption is cool!"
    else:
        f = open(filepath, "rb")
        data = str(f.read())
        f.close()
    # Convert to bytes
    data = bytes(data, "utf-8")
    return data


@app.route("/upload", methods=["POST"])
def upload():
    values = request.get_json()

    # Check posted values
    required = ["sender", "file"]
    if not all(k in values for k in required):
        return "Missing values", 400

    # Extract sender and check if sender is correct
    sender, data = values["sender"], {}
    if blockchain.state.id != str(sender):
        return "Unauthorized", 401

    # Extract file data (un-encrypted version)
    message = file_data(values["file"])

    # Encrypt with public key
    (capsule_hex, ciphertext_hex) = blockchain.state.re_encrypt.encrypt_message(message)

    data["capsule"] = capsule_hex
    data["ciphertext"] = ciphertext_hex
    # Cannot add sender_pk and vk in txn as it would break anonymity
    # data["sender_pk"] = sender_pk_hex
    # data["sender_vk"] = sender_vk_hex
    data_str = json.dumps(data)

    blockchain.new_transaction(sender, "sender", data_str)

    return "OK", 201


def anonymize_receiver(receiver_addr):
    r = PrivateKey.generate()
    R = r.public_key()
    B = PublicKey(Point(bytes.fromhex(receiver_addr))) # Convert point bytes to Public Key
    rB = PublicKey(r.scalar * B.point)
    stealth_address = rB.point.as_bytes().hex()
    shared_randomness = R.point.as_bytes().hex()
    return shared_randomness, stealth_address

@app.route("/share", methods=["POST"])
def share():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ["sender", "recipient", "data_txn_ref"]
    if not all(k in values for k in required):
        return "Missing values", 400
    sender, recipient, data = values["sender"], values["recipient"], {}
    receiver_addr = values['receiver_addr']

    # If I'm not sender --> reject
    if blockchain.state.id != str(sender):
        return "Unauthorized", 401

    # Create a new txn
    receiver_pk_hex = recipient
    data["data_txn_ref"] = values["data_txn_ref"]

    # Anonymize receiver address
    shared_randomness, stealth_address = anonymize_receiver(receiver_addr)

    # TODO: Anonymize
    data["sender_pk"] = bytes(blockchain.state.re_encrypt.re_encrypt_public_key).hex()
    data["verify_pk"] = bytes(blockchain.state.re_encrypt.re_encrypt_verify_key).hex()
    data["shared_randomness"] = shared_randomness  # R = r * G --> r is the secret randomness
    data["stealth_address"] = stealth_address

    data_str = json.dumps(data)
    blockchain.new_transaction(sender, receiver_addr, data_str)

    # Give proxy the reencryption key
    capsule = blockchain.state.get_capsule_from_txn_id(
        values["data_txn_ref"], blockchain.chain
    )
    blockchain.state.re_encrypt.send_reencryption_key_to_proxy(receiver_pk_hex, capsule)

    return "OK", 201


@app.route("/dump", methods=["GET"])
def full_chain():
    response = {
        "chain": [b.encode() for b in blockchain.chain],
        "pending_transactions": [
            txn.encode() for txn in sorted(blockchain.current_transactions)
        ],
        "state": blockchain.state.encode(),
    }
    return jsonify(response), 200


@app.route("/startexp/", methods=["GET"])
def startexp():
    print("Starting experiment with genesis block")
    if blockchain.node_identifier == min(blockchain.nodes):
        blockchain.trigger_new_block_mine(genesis=True)
    return "OK"


@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


if __name__ == "__main__":
    from argparse import ArgumentParser

    logging.getLogger().setLevel(logging.INFO)

    parser = ArgumentParser()
    parser.add_argument(
        "-p", "--port", default=5000, type=int, help="port to listen on"
    )
    parser.add_argument(
        "-t",
        "--blocktime",
        default=5,
        type=int,
        help="Transaction collection time (in seconds) before creating a new block.",
    )
    parser.add_argument(
        "-n",
        "--nodes",
        nargs="+",
        help="ports of all participating nodes (space separated). e.g. -n 5001 5002 5003",
        required=True,
    )
    parser.add_argument(
        "-f", "--filename", type=str, help="json key filename", required=True
    )

    args = parser.parse_args()

    # Use port as node identifier.
    port = args.port
    blockchain.node_identifier = port
    blockchain.block_mine_time = args.blocktime
    blockchain.state.dir = os.path.join(os.getcwd(), str(blockchain.node_identifier))
    blockchain.state.re_encrypt.key_filename = args.filename
    blockchain.state.re_encrypt.setup()
    blockchain.state.id = blockchain.state.re_encrypt.node_id  # TODO: Refactor

    for nodeport in args.nodes:
        blockchain.nodes.append(int(nodeport))

    app.run(host="0.0.0.0", port=port)
