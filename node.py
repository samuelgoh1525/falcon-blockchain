import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request

import pickle

from blockchain import Blockchain
import keys

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

private_key = None

falcon_mode = True

@app.route('/mine', methods=['GET'])
def mine():
    # We must receive a reward for finding the proof.
    # The sender is "__mined__" to signify that this node has mined a new coin.

    #TODO: check transactions valid
    global private_key
    if private_key == None:

        if falcon_mode:
            private_key = keys.generate_private_key(is_falcon=falcon_mode)
        else:
            salt, password = keys.get_salt_password()
            private_key = keys.generate_private_key(password, salt)

    public_key = keys.generate_public_key(private_key, is_falcon=falcon_mode)
    if falcon_mode:
        public_key = {'n': public_key.n, 'h': public_key.h}
        public_key = pickle.dumps(public_key)

    public_key_hex = public_key.hex()

    transaction = blockchain.new_transaction(
        #TODO: sender address for mined
        sender="__mined__",
        #sender=hashlib.sha256("__mined__".encode()).hexdigest(),
        recipient=public_key_hex,
        #TODO: change the amount of coin received, limit total supply of coins
        amount=1,
    )

    signature = keys.sign(transaction, private_key)
    if falcon_mode:
        transaction['signature'] = signature.hex()
    else:
        transaction['signature'] = (signature.signature).hex()
    blockchain.append_transaction(transaction)

    # We run the proof of work algorithm to get the next proof...
    pow_block = blockchain.proof_of_work()

    # Forge the new Block by adding it to the chain
    chain = blockchain.add_block(pow_block)

    response = {
        'message': "New Block Forged",
        'index': pow_block['index'],
        'transactions': pow_block['transactions'],
        'hash': pow_block['hash'],
        'previous_hash': pow_block['previous_hash'],
        #'miner': public_key_hex,
    }
    print("\n", json.dumps(response, indent=2), "\n")
    return jsonify(response), 200

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    response = {
        'pending_transactions': blockchain.current_transactions,
    }
    print("\n", json.dumps(response, indent=2), "\n")
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    #TODO: verify transactions in terms of making sure people do not spend coins they do not own (UTXO model)
    global private_key
    if private_key == None:

        if falcon_mode:
            private_key = keys.generate_private_key(is_falcon=falcon_mode)
        else:
            salt, password = keys.get_salt_password()
            private_key = keys.generate_private_key(password, salt)

    public_key = keys.generate_public_key(private_key, is_falcon=falcon_mode)
    if falcon_mode:
        public_key = {'n': public_key.n, 'h': public_key.h}
        public_key = pickle.dumps(public_key)

    public_key_hex = public_key.hex()

    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    transaction = blockchain.new_transaction(public_key_hex, values['recipient'], values['amount'])

    # Generate signature for transaction
    signature = keys.sign(transaction, private_key)
    if falcon_mode:
        transaction_bytes = json.dumps(transaction, sort_keys=True).encode('utf-8')
        transaction['signature'] = signature.hex()
        valid_sign = keys.verify_sign(transaction_bytes, signature, public_key_hex, is_falcon=falcon_mode)
    else:
        transaction['signature'] = (signature.signature).hex()
        valid_sign = keys.verify_sign(signature.message, signature.signature, public_key_hex)

    index = blockchain.append_transaction(transaction)

    response = {
        'message': f'Transaction will be added to Block {index}',
        'sender': public_key_hex,
        'recipient': values['recipient'],
        'amount': values['amount'],
        'signature': transaction['signature'],
        'valid signature': valid_sign,
    }
    print("\n", json.dumps(response, indent=2), "\n")
    return jsonify(response), 201

@app.route('/chain/get', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    print("\n", json.dumps(response, indent=2), "\n")
    return jsonify(response), 200

@app.route('/chain/valid', methods=['GET'])
def valid_chain():
    valid = blockchain.valid_chain(blockchain.chain)
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'valid' : valid,
    }
    print("\n", json.dumps(response, indent=2), "\n")
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    print("\n", json.dumps(response, indent=2), "\n")
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    print("\n", json.dumps(response, indent=2), "\n")
    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    input_port = input("Enter your port: ")
    use_falcon = input("Use FALCON? (y/n)")
    if use_falcon == 'y':
        falcon_mode = True
    elif use_falcon == 'n':
        falcon_mode = False

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=input_port, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port, use_reloader=False)
