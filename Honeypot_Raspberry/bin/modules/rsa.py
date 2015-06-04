# coding: utf8
#!/usr/bin/env python

import time
import socket
import sys
import getpass
import hashlib
import os
import binascii
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import randpool
from Crypto.Cipher import PKCS1_OAEP

def decryption_RSA(encrypted_message,private_key_server):
        private_key_server = PKCS1_OAEP.new(private_key_server)
        decrypted_message = private_key_server.decrypt(encrypted_message)
        return decrypted_message

def encryption_RSA(plain_text, public_key_client):
        public_key_client = PKCS1_OAEP.new(public_key_client)
        encrypted_message = public_key_server.encrypt(plain_text)
        return encrypted_message

def generate_key():
	pool = randpool.RandomPool()
	crypted_key = RSA.generate(1024, pool.get_bytes)
	private_key_server = crypted_key
	public_key_server = private_key_server.publickey()
	return private_key_server