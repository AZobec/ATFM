# coding: utf8
#!/usr/bin/env python

import time
import sys
import binascii
from Crypto.PublicKey import RSA
from Crypto.Util import randpool
from Crypto.Cipher import PKCS1_OAEP

def decryption(encrypted_message,private_key_server):
        private_key_server = PKCS1_OAEP.new(private_key_server)
        decrypted_message = private_key_server.decrypt(encrypted_message)
        return decrypted_message

def encryption(plain_text, public_key_client):
        public_key_client = PKCS1_OAEP.new(public_key_client)
        encrypted_message = public_key_client.encrypt(plain_text)
        return encrypted_message

def generate_key():
	pool = randpool.RandomPool()
	crypted_key = RSA.generate(1024, pool.get_bytes)
	private_key_server = crypted_key
	public_key_server = private_key_server.publickey()
	return private_key_server