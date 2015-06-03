# coding: utf8
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import PIL.Image
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

BUFFER = 2048

def chiffrement_RSA(plain_text, public_key_server):
        public_key_server = PKCS1_OAEP.new(public_key_server)
        encrypted_message = public_key_server.encrypt(plain_text)
        return encrypted_message

def dechiffrement_RSA(encrypted_message,private_key_client):
        private_key_client = PKCS1_OAEP.new(private_key_client)
        decrypted_message = private_key_client.decrypt(encrypted_message)
        return decrypted_key

def chiffrement(message,key):
        #On créé un nouvel objet
	cipher = AES.new(key)

	# avec AES le message doit être un multiple de 16
	# si ce n'est pas le cas on le complète avec des \0
	if (len(message) % 16) != 0:
		n = 16 - (len(message) % 16)
		for i in range(0, n):
			message += '\0'
	print(len(message))
	# on chiffre symétriquement le contenu du fichier avec notre clé        
	encrypted_aes_message = cipher.encrypt(message)
	return encrypted_aes_message

def dechiffrement(encrypted_aes_message,key):
        cipher = AES.new(key)
	#on déchiffre
	plain_text = cipher.decrypt(encrypted_aes_message)
	#on supprime les \0
	for i in range(0, len(plain_text)):
		if plain_text[i] == 0:
			plain_text = plain_text[0:i]
			break
	print("Voici le message chiffré: ")
	print (plain_text)
	return plain_text

def generate_key():
	pool = randpool.RandomPool()
	crypted_key = RSA.generate(1024, pool.get_bytes)
	private_key_server = crypted_key
	public_key_server = private_key_server.publickey()
	return private_key_server

if __name__ == '__main__':
        
        #Génération de la paire de clé
        private_key_client = generate_key()
        public_key_client = private_key_client.publickey()
        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
                # connexion au serveur, bloc surveillé, et gestion de l'exception
                sock.connect(('127.0.0.1',2020))
        except socket.error:
                print(">>> La connexion a échouée...")
                sys.exit()
        print(">>> Connexion établie avec le serveur...")

        print(">>> Début du TLS Handhake...")
        #Etape 1: envoi Client Hello au serveur
        sock.send(b'Client Hello')

        #Etape 2: reception Server Hello du server      
        if sock.recv(BUFFER)!= b'Server Hello':
                print(">>> Problème TCP : Server Hello : FAILED")
                sock.send(b'FIN')
                sock.close()
                sys.exit()
         #Else du Server Hello                
        else:
                print(">>> Server said : HELLO")
                #Etape 3: reception public key
                time.sleep(0.5)
                public_key_server = RSA.importKey(sock.recv(BUFFER))

                print(">>> Réception de la clé publique")
                #Etape 4: réception du hash de la clé publique
                hash_public_key_server = sock.recv(BUFFER)
                        
        #Comparaison du hash après le server Hello Done
        #Etape 5: réception server hello done
        if sock.recv(BUFFER)!=b'Server Hello done':
                print(">>> Problème TCP : Server Hello Done : FAILED")
                sock.send(b'FIN')
                sock.close()
                sys.exit()
        else:
                #Etape 6: Envoi de la validation du certificat (ok ou nok)
                if hash_public_key_server.decode()==hashlib.sha256(public_key_server.exportKey('DER')).hexdigest():
                        sock.send(b'Certificat OK')
                        print(">>> Le certificat a été \"vérifié\"")

                #Else validation certificat
                else:
                        print(">>> Problème PublicKey : LA CLE NE CORRESPOND PAS AU HASH")
                        sock.send(b'Certificat NOK')
                        sock.close()
                        sys.exit()

        #Etape 7: Envoi de la clé AES
        aes_key = os.urandom(32)
        encrypted_aes_key = chiffrement_RSA(aes_key,public_key_server)
        print("DEBUG : "+ encrypted_aes_key)
        print(">>> La clé a été chiffrée")
        #Envoi de la clé
        sock.send(encrypted_aes_key)
        print(">>> La clé a été envoyée au serveur")
        #Etape 8: Envoi du hash et vérification de la clé de chiffrement
        #Le hash est lui aussi chiffré via RSA
        hash_aes_key = hashlib.sha256(aes_key).hexdigest()
        hash_aes_key = chiffrement_RSA(hash_aes_key,public_key_server)
        time.sleep(0.5)
        sock.send(hash_aes_key)

        #Etape 9: vérification de la clé par retour de OK server sur le hash
        if sock.recv(BUFFER)!=b'AES KEY OK SERVER FINISHED':
                sock.send(b'FIN')
                sock.close()
                sys.exit()
        else:
                print(">>> Le Server a terminé le pseudoTLS Handshake")
                print(">>> Début de la communication chiffrée")
        #on a la boucle de communication habituelle
        while 1:
                toclientmessage = input("Message:")
                if toclientmessage == "FIN":
                    toclientmessage = chiffrement(toclientmessage,aes_key)
                    sock.send(toclientmessage)
                elif toclientmessage == "TEST":
                    toclientmessage = chiffrement(toclientmessage,aes_key)
                    sock.send(toclientmessage)
                msgServer=sock.recv(BUFFER)
                testMessageServer=dechiffrement(msgServer.decode(),aes_key)
                if testMessageServer=="FIN":
                    break
                elif testMessageServer == "TEST OK":
                    sock.send((chiffrement('FIN'),aes_key).encode())
                    break
    
        #Fin while (1) connexion
        print (">>> Connexion interrompue proprement par le serveur")
        sock.close()
        sys.exit()