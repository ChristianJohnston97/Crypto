import hashlib
import os
import json
from hashlib import sha256
from time import time
import ecdsa

from uuid import uuid4

from flask import Flask, jsonify, request

from urllib.parse import urlparse

# To run: python3.7 hashlib_test.py

#################### 

### Resources ###
# https://hackernoon.com/learn-blockchains-by-building-one-117428612f46
# https://github.com/dvf/blockchain/blob/master/blockchain.py

####################

class Blockchain(object):
    def __init__(self):
        # initialises the class with an empty blockchain and an
        # empty list of current transactions
        self.chain = []
        self.current_transactions = []
        
        # cant have duplicate nodes
        self.nodes = set()

    # Add a new node to the list of nodes
    # address is the url of the node eg: 'http://192.168.0.5:5000'
    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    # Determine if a given blockchain is valid
    # by looping through each block and verifying both the hash and the proof.
    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False
            last_block = block
            current_index += 1
        return True

    # replaces the chain with the longest one in the network.
    # returns True if our chain was replaced, False if not
    # loops through all our neighbouring nodes, downloads their chains and verifies them 
    # If a valid chain is found, whose length is greater than ours, we replace ours.
    def resolve_conflicts(self):
            neighbours = self.nodes
            new_chain = None

            # We're only looking for chains longer than ours
            max_length = len(self.chain)

            # Grab and verify the chains from all the nodes in our network
            for node in neighbours:
                response = requests.get(f'http://{node}/chain')

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


    # Creates a Genesis Block with empty transactions and no previous hash
    def create_genesis_block(self):
        genesis_block = {
        'index': 0,
        'timestamp': time(),
        'transactions': [],
        'proof': 1,
        'previous_hash': None
        }
        self.chain.append(genesis_block)
        return genesis_block

    # hashing a message using sha256
    @staticmethod
    def hash(message):
    	hashed_message = hashlib.sha256((message).encode())
    	hashed_message_hex = hashed_message.hexdigest()
    	return hashed_message_hex

    # hash a block of data
    def hash_block(self, block):
        # json module to serialise python dictionary objects before hashing them
    	block_serialized = json.dumps(block, sort_keys=True)
    	block_hash = hash(block_serialized)
    	return block_hash

    # de-serialised data block to access the data contained
    def deserialise(serialised_data_block):
        data_block = json.loads(serialised_data_block)
        return data_block


    # hash a list of blocks, linking each one to the previous
    def hash_blocks(blocks):
    	prev_hash = None
    	for block in blocks:
    		block['prev_hash'] = prev_hash
    		block_hash = hash_block(block)
    		prev_hash = block_hash
    	return prev_hash


    # create and sign a new transaction
    def submit_transaction(self, sender, recipient, amount):
        global current_transactions

        transaction = {
        'sender': sender,
        'recipient': recipient,
        'amount': amount
        }
        # sign the transaction
        sig, vk = signBlock(transaction)

        transaction_with_signature = (transaction, sig)

        # add the transaction (with signature) to the list of transactions
        self.current_transactions.append(transaction)

        # index of the block in the blockchain 
        block = self.getLastBlock()
        block_index = block["index"] + 1

        return block_index


    def new_block(self, proof):
        global current_transactions

        # gets the hash of the last block on the blockchain 
        previous_block = self.getLastBlock()
        previous_block_hash = self.hash_block(previous_block)

        block = {
        'index': len(self.chain) + 1,
        'timestamp': time(),
        'transactions': self.current_transactions,
        'proof': proof,
        'previous_hash': previous_block_hash
        }
        self.current_transactions = []
        self.chain.append(block)
        return block


    # get the last block in the chain
    def getLastBlock(self):
    	return self.chain[-1]

        
    # Find a number p' such that hash(pp') contains leading 4 zeroes
    # p is the previous proof, and p' is the new proof        
    def proof_of_work(self, last_block):
    	last_proof = last_block['proof']
    	last_block_hash = self.hash_block(last_block)
    	proof = 0
    	while self.valid_proof(last_proof, proof, last_block_hash) is False:
    		proof += 1
    	return proof

    # 'proof' is essentially a nonce
    def valid_proof(self, last_proof, proof, last_block_hash):
        # string concatenation
    	guess = f'{last_proof}{proof}{last_block_hash}'
    	guess_hash = self.hash(guess)
    	return guess_hash[:4] == "0000"


   # verify if a given item of data is in a data block with given index
    def verifyDataItem(self, index, sender, recipient, amount):
        block = chain[index]
        # loop through list of transactions
        for transaction_tuple in block["transactions"]:  
            # transaction is the first in the tuple (transaction, signature)
            transaction = transaction_tuple[0]
            if(transaction["recipient"] == recipient and transaction["sender"] == sender and transaction["amount"] == amount):
                return True
        return False

    # verify whether each block in the list contains a correct hash of the previous block
    def verify_block(self, block):
        # check all the transactions for valid signatures
        for transaction in block["transactions"]:
            if(not verifySignature(transaction)):
                return False

        # check the previous hash matches
        indexOfPreviousBlock = block["index"] - 1
        if(block["previous_hash"] == self.hash_block(self.chain[indexOfPreviousBlock-1])):
            return True
        else:
            return False

    # verify every block in the blockchain
    # do not check the genesis block
    def verify_blockchain(self):
        for block in self.chain[1:]:
            if(self.verify_block(block) == False):
                return False
        return True

  ################################
    ### ecdsa for signatures ###
  ################################

# generate a signing key pair 
def generateKeyPair():

    # sk is the signing key (private)
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) 

    # vk is the verifying key (public)
    vk = sk.get_verifying_key()

    return sk, vk

# sign a transaction by generating a key pair
def signBlock(block):

    # generate key pair
    sk, vk = generateKeyPair()

    #serialise
    block_serialized = json.dumps(block, sort_keys=True)

    # hash the data block
    hashed_block = hashlib.sha256((block_serialized).encode()).hexdigest()

    # convert to a byte array
    hashed_block = bytearray(hashed_block, 'utf8')

    # sign a byte encoded message with private key
    sig = sk.sign(hashed_block)

    # return the signature and the verifying key
    return sig, vk

# verify a signature
def verifySignature(vk, sig, block):
    #serialize
    block_serialized = json.dumps(block, sort_keys=True)

    # hash the serialised data block
    hashed_block = hashlib.sha256((block_serialized).encode()).hexdigest()

    # convert to a byte array
    hashed_block = bytearray(hashed_block, 'utf8')

    # assert whether true 
    assert vk.verify(sig, hashed_block)

####################

# Python Flask Framework: allows us talk to our blockchain over the web using HTTP requests

# /transactions/new to create a new transaction to a block
# /mine to tell our server to mine a new block.
# /chain to return the full Blockchain.

# Instantiate our Node
app = Flask(__name__)

# instantiate the blockchains
blockchain = Blockchain()

# create a genesis block
block_1 = blockchain.create_genesis_block()




# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')


# get request to mine a new block
@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.getLastBlock()
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.submit_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    previous_hash = blockchain.hash_block(last_block)
    block = blockchain.new_block(proof)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash']
    }

    # need to convert bytes to string 

    response = str(response)

    return jsonify(response), 200


# post request to add a new transaction
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.submit_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


# get request to get full blockchain back
# allows other servers to maintain a copy of the blockchain
@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


# register a new node
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
    return jsonify(response), 201

# resolve conflicts
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

    return jsonify(response), 200


# runs the Flask server on port 50000
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)




