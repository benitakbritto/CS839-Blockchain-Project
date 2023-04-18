# Usage: python3 server.py -p 5001 -n 5001 5002 5003 -f 5001.json
from flask import Flask, request, jsonify
import logging
import blockchain as bc
import os
import json

# Instantiate the Node
app = Flask(__name__)

# Instantiate the Blockchain
blockchain = bc.Blockchain()

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

    # Modify in-memory data structures to reflect the new block
    blockchain.chain.append(block)   
    blockchain.state.apply_block(block)

    # if I am responsible for next block, start mining it (trigger_new_block_mine).
    max_node_id, min_node_id = max(blockchain.nodes), min(blockchain.nodes)
    next_miner_id = min_node_id + ((block.miner + 1 - min_node_id) % \
        (max_node_id - min_node_id + 1))
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
    logging.info('[DEBUG] Inside new_transaction')
    values = request.get_json()
    logging.info(values)

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient']
    if not all(k in values for k in required):
        return 'Missing values', 400
    
    logging.info('[DEBUG] Meets requirement')

    sender, recipient, data = values['sender'], values['recipient'], {}
    logging.info(sender)
    logging.info(type(sender))
    logging.info(recipient)
    logging.info(blockchain.node_identifier)
    logging.info(blockchain.state.id)

    # If I'm not sender --> reject, for the time being
    if blockchain.state.id != str(sender):
        return 'Unauthorized', 401

    # TODO: Need to get a way for receiver_public_key    
    # Send data    
    receiver_public_key_hex = '0333d18ef2e3a6a2489b94853d3f32becdb75cdba7027a9abe2877a9a2c782e0c8'
    
    capsule_hex, ciphertext_hex, sender_pk_hex, sender_vk_hex = \
        blockchain.state.re_encrypt.encrpyt_message(receiver_public_key_hex)
    data['capsule'] = capsule_hex
    data['ciphertext'] = ciphertext_hex
    data['sender_pk'] = sender_pk_hex
    data['sender_vk'] = sender_vk_hex
    
    logging.info('[DEBUG] Returned from encrypt')
    logging.info(data)
        
    # Create a new Transaction
    data_str = json.dumps(data)
    logging.info(data_str)
    
    logging.info('[DEBUG] Calling new txn')
    blockchain.new_transaction(sender, recipient, data_str)
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

if __name__ == '__main__':
    from argparse import ArgumentParser
    logging.getLogger().setLevel(logging.INFO)

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, \
        help='port to listen on')
    parser.add_argument('-t', '--blocktime', default=5, type=int, \
        help='Transaction collection time (in seconds) before creating a new block.')
    parser.add_argument('-n', '--nodes', nargs='+', \
        help='ports of all participating nodes (space separated). e.g. -n 5001 5002 5003', \
        required=True)
    parser.add_argument('-f', '--filename', type=str, \
        help='json key filename', \
        required=True)

    args = parser.parse_args()

    # Use port as node identifier.
    port = args.port    
    blockchain.node_identifier = port
    blockchain.block_mine_time = args.blocktime
    blockchain.state.dir = os.path.join(os.getcwd(), str(blockchain.node_identifier))
    blockchain.state.re_encrypt.key_filename = args.filename
    blockchain.state.re_encrypt.setup()
    blockchain.state.id = blockchain.state.re_encrypt.node_id # TODO: Refactor

    for nodeport in args.nodes:
        blockchain.nodes.append(int(nodeport))
    
    app.run(host='0.0.0.0', port=port)
