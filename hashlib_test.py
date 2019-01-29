import hashlib
import os
import json
from hashlib import sha256
from time import time
import ecdsa



#################### 
### Resources ###
# https://hackernoon.com/learn-blockchains-by-building-one-117428612f46

####################
# Questions

# 1. Where do you store the signature of the transaction? (tuple?)


################      
    # hashlib             
################      

class Blockchain(object):
    def __init__(self):
        # initialises the class with an empty blockchain and an
        # empty list of current transactions
        self.chain = []
        self.current_transactions = []
        # Creates a Genesis Block with empty transactions

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

        transaction = {
        'sender': sender,
        'recipient': recipient,
        'amount': amount
        }
        # sign the transaction
        sig, vk = signTransaction(transaction)

        # add the transaction (with signature) to the list of transactions
        current_transactions.append(transaction, sig)

        # index of the block in the blockchain 
        block_index = getLastBlock(self.chain).index + 1

        return block_index, sig, transaction, vk


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
    def proof_of_work(last_block):
    	last_proof = last_block['proof']
    	last_hash = hash(last_block)
    	proof = 0
    	while valid_proof(last_proof, proof, last_hash) is False:
    		proof += 1
    	return proof

    # validates the proof
    # 'proof' is essentially a nonce
    def valid_proof(last_proof, proof, last_hash):
    	guess = f'{last_proof}{proof}{last_hash}'
    	guess_hash = hashMessage(guess)
    	return guess_hash[:4] == "0000"


   # verify if a given item of data is in a data block with given index
    def verifyDataItem(self, index, sender, recipient, amount):
        block = chain[index]
        # loop through list of transactions
        for transaction in block["transactions"]:  
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

  ################
    ### ecdsa ###
  ################

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
    # hash the data block
    hashed_block = hashlib.sha256((block_serialized).encode()).hexdigest()

    # convert to a byte array
    hashed_block = bytearray(hashed_block, 'utf8')

    # assert whether true 
    assert vk.verify(sig, hashed_block)

####################
# Testing

blockchain = Blockchain()

# create a hash-linked list of data blocks
block_1 = blockchain.create_genesis_block()
hash_block_1 = blockchain.hash_block(block_1)
block_2 = blockchain.new_block(proof = 1)
hash_block_2 = blockchain.hash_block(block_2)
block_3 = blockchain.new_block(proof = 1)
hash_block_3 = blockchain.hash_block(block_3)
block_4 = blockchain.new_block(proof = 1)

# verify the blockchain
blockchain.verify_blockchain()

# testing signature verification
sig, vk = signBlock(block_4)
verifySignature(vk, sig, block_4)



