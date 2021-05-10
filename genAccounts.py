import codecs
import ecdsa
import json
import sys
from time import strftime, gmtime
from web3 import Web3
from Crypto.Hash import keccak
import os

keys = []

def generate_accounts(number_of_accounts):
    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": trying to generate " + str(number_of_accounts) + " key pairs")
    for i in range(number_of_accounts):
        private_key_bytes = os.urandom(32)
        key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        private_key = codecs.encode(private_key_bytes, 'hex')
        public_key = codecs.encode(key_bytes, 'hex')
        public_key_bytes = codecs.decode(public_key, 'hex')
        hash = keccak.new(digest_bits=256)
        hash.update(public_key_bytes)
        keccak_digest = hash.hexdigest()
        address = '0x' + keccak_digest[-40:]
        keys.append({"address": Web3.toChecksumAddress(address), "private_key": codecs.decode(private_key)})

    with open('new_keys.py', 'w') as outfile:
        json.dump(keys, outfile)
    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": succufully generated " + str(len(keys)) + " key pairs")