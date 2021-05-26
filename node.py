import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request

import pickle

from blockchain import Blockchain
from utxo import UTXO
import keys

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

# Instantiate the UTXO set
utxo_set = UTXO()


private_key = None

falcon_mode = True

@app.route('/mine', methods=['GET'])
def mine():
    # We must receive a reward for finding the proof.
    # The sender is "__mined__" to signify that this node has mined a new coin.

    #TODO: check transactions valid

    # We also need to modify the UTXO set accordingly
    # 1) Remove the spent transaction outputs
    # 2) Add the new unspent transaction outputs
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

    block_index = blockchain.last_block['index'] + 1

    mined_input = [{
        'id': 'mined',
        'output_index': 'mined',
        'block_index': block_index,
        'amount': 100,
    }]

    signature = keys.sign(mined_input, private_key)
    if falcon_mode:
        mined_input[0]['signature'] = signature.hex()
    else:
        mined_input[0]['signature'] = (signature.signature).hex()

    mined_output = [{
        'amount': 100,
        'address': public_key_hex,
    }]

    utxo_set.mine_new_coins(100)

    transaction = {
        'inputs': mined_input,
        'outputs': mined_output,
    }

    transaction_string = json.dumps(transaction, sort_keys=True).encode()
    transaction['id'] = hashlib.sha256(transaction_string).hexdigest()

    #utxo_set.add_utxo(transaction['id'], 0, block_index, transaction['outputs'][0]['amount'], transaction['outputs'][0]['address'])

    '''
    transaction = blockchain.new_transaction(
        #TODO: sender address for mined
        sender="__mined__",
        #sender=hashlib.sha256("__mined__".encode()).hexdigest(),
        recipient=public_key_hex,
        amount=100,
    )

    signature = keys.sign(transaction, private_key)
    if falcon_mode:
        transaction['signature'] = signature.hex()
    else:
        transaction['signature'] = (signature.signature).hex()
    '''
    blockchain.append_transaction(transaction)

    # We run the proof of work algorithm to get the next proof...
    pow_block = blockchain.proof_of_work()

    # Forge the new Block by adding it to the chain
    chain, all_transactions = blockchain.add_block(pow_block)

    # Add new unspent transaction outputs to utxo set
    # Remove the spent transaction outputs
    for transaction in all_transactions:
        utxo_set.modify_utxo(transaction, public_key_hex, pow_block['index'])

    response = {
        'message': "New Block Forged",
        'index': pow_block['index'],
        'transactions': pow_block['transactions'],
        'hash': pow_block['hash'],
        'previous_hash': pow_block['previous_hash'],
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
        public_key_pickled = pickle.dumps({'n': public_key.n, 'h': public_key.h})
        public_key_hex = public_key_pickled.hex()

    else:
        public_key_hex = public_key.hex()

    values = request.get_json()

    required = ['recipients', 'amounts']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    # TODO: error checking if not enough coins
    transaction = utxo_set.make_transaction(public_key_hex, values['recipients'], values['amounts'], private_key, falcon_mode)

    '''
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
    '''
    index = blockchain.append_transaction(transaction)

    response = {
        'message': f'Transaction will be added to Block {index}',
        'transaction': transaction,
        #'sender': public_key_hex,
        #'recipients': values['recipients'],
        #'amounts': values['amounts'],
        #'signature': transaction['signature'],
        #'valid signature': valid_sign,
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


@app.route('/utxo/all', methods=['GET'])
def get_utxo_all():
    response = {
        'utxo_all': utxo_set.transaction_outputs,
    }
    print("\n", json.dumps(response, indent=2), "\n")
    return jsonify(response), 200


@app.route('/utxo/user', methods=['GET'])
def get_utxo_user():
    values = request.get_json()

    required = ['user']
    if not all(k in values for k in required):
        return 'Missing values', 400

    response = {
        'address': values['user'],
        'utxo_user': utxo_set.get_user_amount(values['user']),
    }
    print("\n", json.dumps(response, indent=2), "\n")
    return jsonify(response), 200

@app.route('/utxo/unmined', methods=['GET'])
def get_utxo_unmined():
    response = {
        'unmined': utxo_set.unmined,
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
