import hashlib
import json
from unittest import TestCase

from blockchain import Blockchain


class BlockchainTestCase(TestCase):

    def setUp(self):
        self.blockchain = Blockchain()

    def create_block(self, previous_hash='abc'):
        block = self.blockchain.new_block(previous_hash)
        current_hash = self.blockchain.hash(block)
        block['hash'] = current_hash
        self.blockchain.add_block(block)

    def create_transaction(self, sender='a', recipient='b', amount=1, signature='test'):
        # TODO: check signature properly with sender public key
        # change the bottom two tests also
        self.blockchain.new_transaction(
            sender=sender,
            recipient=recipient,
            amount=amount,
            signature=signature
        )


class TestRegisterNodes(BlockchainTestCase):

    def test_valid_nodes(self):
        blockchain = Blockchain()

        blockchain.register_node('http://192.168.0.1:5000')

        self.assertIn('192.168.0.1:5000', blockchain.nodes)

    def test_malformed_nodes(self):
        blockchain = Blockchain()

        blockchain.register_node('http//192.168.0.1:5000')

        self.assertNotIn('192.168.0.1:5000', blockchain.nodes)

    def test_idempotency(self):
        blockchain = Blockchain()

        blockchain.register_node('http://192.168.0.1:5000')
        blockchain.register_node('http://192.168.0.1:5000')

        assert len(blockchain.nodes) == 1


class TestBlocksAndTransactions(BlockchainTestCase):

    def test_block_creation(self):
        self.create_block()

        latest_block = self.blockchain.last_block

        # The genesis block is create at initialization, so the length should be 2
        assert len(self.blockchain.chain) == 2
        assert latest_block['index'] == 2
        assert latest_block['timestamp'] is not None
        block_without_hash = latest_block.copy()
        block_without_hash.pop('hash')
        assert latest_block['hash'] == self.blockchain.hash(block_without_hash)
        assert latest_block['previous_hash'] == 'abc'

    def test_create_transaction(self):
        self.create_transaction()

        transaction = self.blockchain.current_transactions[-1]

        assert transaction
        assert transaction['sender'] == 'a'
        assert transaction['recipient'] == 'b'
        assert transaction['amount'] == 1

    def test_block_resets_transactions(self):
        self.create_transaction()

        initial_length = len(self.blockchain.current_transactions)

        self.create_block()

        current_length = len(self.blockchain.current_transactions)

        assert initial_length == 1
        assert current_length == 0

    def test_return_last_block(self):
        self.create_block()

        created_block = self.blockchain.last_block

        assert len(self.blockchain.chain) == 2
        assert created_block is self.blockchain.chain[-1]


class TestHashingAndProofs(BlockchainTestCase):

    def test_hash_is_correct(self):
        self.create_block()

        new_block = self.blockchain.last_block
        new_block_json = json.dumps(self.blockchain.last_block, sort_keys=True).encode()
        new_hash = hashlib.sha256(new_block_json).hexdigest()

        assert len(new_hash) == 64
        assert new_hash == self.blockchain.hash(new_block)
