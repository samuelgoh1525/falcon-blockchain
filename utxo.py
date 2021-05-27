import copy
import hashlib
import json

import keys

class UTXO:
    '''
    Format of transactions <dict>:
    - id (hash)
    - <list> inputs:
        <dict>
        - id (-1 for mined coins)
        - output_index (-1 for mined coins)
        - block_index
        - amount
        - signature
    - <list> outputs
        <dict>
        - amount
        - address (public key)
    '''
    def __init__(self):
        # List of (unspent) transaction outputs
        '''
        UTXO format:
            <list> dict:
                - id
                - output_index
                - block_index

                - amount
                - address
        '''
        self.transaction_outputs = []

        # Remaining coins to be mined
        self.unmined = 24000000

    def mine_new_coins(self, amount):
        self.unmined -= amount
        return self.unmined

    def get_user_amount(self, user):
        total = 0

        for output in self.transaction_outputs:

            if output['address'] == user:
                total += output['amount']

        return total

    def add_utxo(self, id_in, output_index_in, block_index_in, amount_in, address_in):
        tx = {
            'id': id_in,
            'output_index': output_index_in,
            'block_index': block_index_in,
            'amount': amount_in,
            'address': address_in,
        }
        self.transaction_outputs.append(tx)
        return tx

    def modify_utxo(self, transaction, user_addr, block_index):
        for input in transaction['inputs']:
            # Remove these from the utxo set
            # Except if they are newly mined coins
            if (input['id'] != 'mined') and (input['output_index'] != 'mined'):
                tx_remove = {
                    'id': input['id'],
                    'output_index': input['output_index'],
                    'block_index': input['block_index'],
                    'amount': input['amount'],
                    'address': user_addr,
                }
                self.transaction_outputs.remove(tx_remove)

        index = 0
        for output in transaction['outputs']:
            # Add these to the utxo set
            tx_add = {
                'id': transaction['id'],
                'output_index': index,
                'block_index': block_index,
                'amount': output['amount'],
                'address': output['address'],
            }
            self.transaction_outputs.append(tx_add)
            index += 1

        return self.transaction_outputs

    def assign_block_index(self, transaction, block_index):
        index = 0
        for output in transaction['outputs']:
            # Assign block index to the utxo set
            tx_to_find = {
                'id': transaction['id'],
                'output_index': index,
                'block_index': None,
                'amount': output['amount'],
                'address': output['address'],
            }
            try:
                tx_index = self.transaction_outputs.index(tx_to_find)
                self.transaction_outputs[tx_index]['block_index'] = block_index
            except ValueError:
                return False
            index += 1

        return True
    def make_transaction(self, sender, recipients, amounts, sender_key, is_falcon):
        # Note: recipients and amounts are <lists>

        total_amount = sum(amounts)
        sender_balance = 0
        tx_in = []

        # Outputs of the transaction
        tx_out = []

        for i in range(len(recipients)):
            tx = {
                'amount': amounts[i],
                'address': recipients[i],
            }
            tx_out.append(tx)

        # Search the UTXO set for coins adding up to at least the total amount
        # These will be the inputs for the transaction
        # Additional coins will be returned to the user as change
        for output in self.transaction_outputs:

            if sender_balance >= total_amount:
                # Once we have enough coins, stop searching
                break

            elif output['address'] == sender:
                sender_balance += output['amount']

                utxo_entry = copy.deepcopy(output)
                utxo_entry.pop('address')

                # For each input, generate a signature with the sender's private key
                signature = keys.sign(utxo_entry, sender_key)
                if is_falcon:
                    utxo_entry['signature'] = signature.hex()
                else:
                    utxo_entry['signature'] = (signature.signature).hex()

                tx_in.append(utxo_entry)

        # Check if sender has enough coins
        # Or if excess coins need to be returned as change
        remainder = sender_balance - total_amount

        if remainder < 0:
            # Not enough coins

            return None

        elif remainder > 0:
            # Create additional transaction to return change to sender
            tx = {
                'amount': remainder,
                'address': sender,
            }
            tx_out.append(tx)

        transaction = {
            'inputs': tx_in,
            'outputs': tx_out,
        }

        # Transaction ID is just a unique hash to identify the transaction
        transaction_string = json.dumps(transaction, sort_keys=True).encode()
        transaction['id'] = hashlib.sha256(transaction_string).hexdigest()

        return transaction
