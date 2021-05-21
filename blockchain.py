import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import random

import requests

import keys


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        genesis_block = self.new_block(previous_hash='genesis')
        genesis_block['hash'] = self.hash(genesis_block)
        self.add_block(genesis_block)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        # Check genesis block
        if not self.valid_proof(last_block, last_block['hash'], genesis=True):
            return False

        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            '''
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            '''
            # Check that the hash of the block is correct
            if block['previous_hash'] != last_block['hash']:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(block, block['hash']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain/get')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, previous_hash=None):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'previous_hash': previous_hash or self.chain[-1]['hash'],
            'nonce': format(random.getrandbits(64), "x")
        }

        return block

    def add_block(self, block):

        # Reset the current list of transactions
        #TODO: remove all transactions? or only remove transactions that have been verified
        self.current_transactions = []

        self.chain.append(block)
        return self.chain

    @staticmethod
    def new_transaction(sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender (Public Key[in Hex] of Sender)
        :param recipient: Address of the Recipient (Public Key of Recipient)
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        }

        return transaction

    def append_transaction(self, transaction):
        self.current_transactions.append(transaction)
        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        """
        Simple Proof of Work Algorithm:

         - Find a new block such that the hash of the block has 4 leading zeros

        :return: <dict> Block validated by POW
        """
        found_proof = False
        while not found_proof:
            block = self.new_block()
            proof = self.hash(block)

            if(self.valid_proof(block, proof)):
                found_proof = True
                block['hash'] = proof

        return block

    @staticmethod
    def valid_proof(block, hash, genesis=False):
        """
        Validates the Proof

        :param block: <dict> Block to be validated
        :param hash: <int> Current block hash
        :return: <bool> True if correct, False if not.

        """
        valid = False
        block_without_hash = block.copy()
        block_without_hash.pop('hash', None)

        if hash == Blockchain.hash(block_without_hash):

            if genesis:
                valid = True

            elif hash[:4] == "0000":
                valid = True

            else:
                valid = False

        else:
            valid = False

        return valid
