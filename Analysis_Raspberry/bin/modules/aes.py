# coding: utf8
#!/usr/bin/env python

import time
import binascii
import random
import os
import struct
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP

def encryption(message,key):
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

def decryption(message,key):
	cipher = AES.new(key)
	#on déchiffre
	plain_text = cipher.decrypt(message).replace('\0', '')
	#on supprime les \0
	for i in range(0, len(plain_text)):
		if plain_text[i] == 0:
			plain_text = plain_text[0:i]
			break
	return plain_text

def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
	#Thanks to Eli Bendersky
	if not out_filename:
		out_filename = in_filename + '.enc'

	iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
	encryptor = AES.new(key, AES.MODE_CBC, iv)
	filesize = os.path.getsize(in_filename)

	with open(in_filename, 'rb') as infile:
		with open(out_filename, 'wb') as outfile:
			outfile.write(struct.pack('<Q', filesize))
			outfile.write(iv)

			while True:
				chunk = infile.read(chunksize)
				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
					chunk += ' ' * (16 - len(chunk) % 16)

				outfile.write(encryptor.encrypt(chunk))

def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
	#Thanks to Eli Bendersky
	if not out_filename:
		out_filename = os.path.splitext(in_filename)[0]

	with open(in_filename, 'rb') as infile:
		origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
		iv = infile.read(16)
		decryptor = AES.new(key, AES.MODE_CBC, iv)

		with open(out_filename, 'wb') as outfile:
			while True:
				chunk = infile.read(chunksize)
				if len(chunk) == 0:
					break
				outfile.write(decryptor.decrypt(chunk))
			outfile.truncate(origsize)