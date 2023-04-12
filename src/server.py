from flask import Flask, request, jsonify
import logging
import blockchain as bc
import rsa
from cryptography.fernet import Fernet
import os
import json

# Instantiate the Node
app = Flask(__name__)

# Instantiate the Blockchain
blockchain = bc.Blockchain()
public_key, private_key = rsa.newkeys(512)
# Public keys of all nodes- node id --> key
print(f"Node {blockchain.node_identifier} public key: {public_key.save_pkcs1().decode('utf-8')}, private key: {private_key.save_pkcs1().decode('utf-8')}")

def generate_symmetric_keys(node_ids):
    # Generate separate symmetric Keys for sending data to other nodes
    symm_keys = {str(node_id): Fernet.generate_key() for node_id in node_ids}
    fernets = {node_id: Fernet(key) for (node_id, key) in symm_keys.items()}
    return symm_keys, fernets

@app.route('/inform/block', methods=['POST'])
def new_block_received():
    values = request.get_json()
    logging.info("Received: " + str(values))

    # Check that the required fields are in the POST'ed data
    required = ['number', 'transactions', 'miner', 'previous_hash', 'hash']
    if not all(k in values for k in required):
        logging.warning("[RPC: inform/block] Missing values")
        return 'Missing values', 400

    block = bc.Block.decode(values)
    valid = blockchain.is_new_block_valid(block, values['hash'])

    if not valid:
        logging.warning("[RPC: inform/block] Invalid block")
        return 'Invalid block', 400

    blockchain.chain.append(block)    # Add the block to the chain
    # Modify any other in-memory data structures to reflect the new block
    # After receiving genesis block, set state to 5001:10000
    if block.number == 1:
        blockchain.state.balance['5001'] = 10000
        blockchain.state.history_log[1] = {'5001': 10000}
    else:
        blockchain.state.apply_block(block)

    # TODO: if I am responsible for next block, start mining it (trigger_new_block_mine).
    max_node_id, min_node_id = max(blockchain.nodes), min(blockchain.nodes)
    next_miner_id = min_node_id + ((block.miner + 1 - min_node_id) % (max_node_id - min_node_id + 1))
    if next_miner_id == blockchain.node_identifier:
        blockchain.trigger_new_block_mine()

    return "OK", 201


def file_data_encrypted(filepath, symm_key):
    if not os.path.isfile(filepath): data = "default hello world message"
    else:
        f = open(filepath, 'rb')
        data = str(f.read())

    # Encrypt huge file data
    data_encrypted = symm_key.encrypt(data.encode()).decode('utf-8')
    # Get bytes from string
    assert(symm_key.decrypt(bytes(data_encrypted, 'utf-8')).decode()) == data

    return data_encrypted

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    sender, recipient, amount, data = values['sender'], values['recipient'], int(values['amount']), {}

    # If I'm not sender --> reject, for the time being
    if blockchain.node_identifier != int(sender):
        return 'Unauthorized', 401

    # I am the sender- send public key by default
    data['pub_key'] = public_key.save_pkcs1().decode('utf-8') # Default data is encoded public key
    print(recipient)
    print(blockchain.state.public_keys)
    if recipient in blockchain.state.public_keys:
        symm_key_enc = rsa.encrypt(symm_keys[recipient], blockchain.state.public_keys[recipient]).hex()
        data['symm_key'] = symm_key_enc
        print("Sending encrypted symmetric key to recipient: ", recipient)
    # Send data if it is present
    if 'data' in values:
        filename = values['data']
        filepath = os.path.join(blockchain.state.dir, filename)
        data['data'] = file_data_encrypted(filepath, fernets[recipient]) # specify filepath in data --> encrypt file and send

    # Create a new Transaction
    data = json.dumps(data)
    blockchain.new_transaction(sender, recipient, amount, data)
    return "OK", 201


@app.route('/dump', methods=['GET'])
def full_chain():
    response = {
        'chain': [b.encode() for b in blockchain.chain],
        'pending_transactions': [txn.encode() for txn in sorted(blockchain.current_transactions)],
        'state': blockchain.state.encode()
    }
    return jsonify(response), 200

@app.route('/startexp/', methods=['GET'])
def startexp():
    print("Starting experiment with genesis block")
    if blockchain.node_identifier == min(blockchain.nodes):
        blockchain.trigger_new_block_mine(genesis=True)
    return 'OK'

@app.route('/health', methods=['GET'])
def health():
    return 'OK', 200

@app.route('/history', methods=['GET'])
def history():
    account = request.args.get('account', '')
    if account == '':
        return 'Missing values', 400
    data = blockchain.state.history(account)
    return jsonify(data), 200

if __name__ == '__main__':
    from argparse import ArgumentParser
    logging.getLogger().setLevel(logging.INFO)

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-t', '--blocktime', default=5, type=int, help='Transaction collection time (in seconds) before creating a new block.')
    parser.add_argument('-n', '--nodes', nargs='+', help='ports of all participating nodes (space separated). e.g. -n 5001 5002 5003', required=True)

    args = parser.parse_args()

    # Use port as node identifier.
    port = args.port    
    blockchain.node_identifier = port
    blockchain.block_mine_time = args.blocktime
    blockchain.state.private_key = private_key
    blockchain.state.id = port
    blockchain.state.dir = os.path.join(os.getcwd(), str(blockchain.node_identifier))

    for nodeport in args.nodes:
        blockchain.nodes.append(int(nodeport))
    
    symm_keys, fernets = generate_symmetric_keys(blockchain.nodes)
    print("Symmetric keys: ", symm_keys)
    print("Fernets: ", fernets)

    app.run(host='0.0.0.0', port=port)
