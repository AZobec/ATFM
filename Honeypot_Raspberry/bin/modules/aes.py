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

def encryption_aes(message,key):
        #On créé un nouvel objet
	cipher = AES.new(key)

	# avec AES le message doit être un multiple de 16
	# si ce n'est pas le cas on le complète avec des \0
	if (len(message) % 16) != 0:
		n = 16 - (len(message) % 16)
		for i in range(0, n):
			message += '\0'
	# on chiffre symétriquement le contenu du fichier avec notre clé        
	encrypted_message = cipher.encrypt(message)
	return encrypted_message

def decryption_aes(message,key):
    cipher = AES.new(key)
	#on déchiffre
	plain_text = cipher.decrypt(message)
	#on supprime les \0
	for i in range(0, len(plain_text)):
		if plain_text[i] == 0:
			plain_text = plain_text[0:i]
			break
	return plain_text