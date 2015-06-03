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

def dechiffrement_RSA(encrypted_message,private_key_server):
        private_key_server = PKCS1_OAEP.new(private_key_server)
        decrypted_message = private_key_server.decrypt(encrypted_message)
        return decrypted_message

def chiffrement_RSA(plain_text, public_key_client):
        public_key_client = PKCS1_OAEP.new(public_key_client)
        encrypted_message = public_key_server.encrypt(plain_text)
        return encrypted_message

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
	encode = cipher.encrypt(message)
	return encode

def dechiffrement(message,key):
        cipher = AES.new(key)
	#on déchiffre
	plain_text = cipher.decrypt(message)
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
    private_key_server = generate_key()
    public_key_server = private_key_server.publickey()
    
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    HOST='127.0.0.1'
    PORT=2020


    testMessageClient=""

    #CrÃ©ation d'une socket avec la famille IP + TCP
    MySocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #Liaison Socket avec adresse+PORT
    MySocket.bind((HOST, PORT))

    while True:
            #Boucle de traitement tant qu'il y a des clients connectÃ©s
            print("S > Serveur prêt, en attente d'un client")

            #ecoute d'une connexion et une seule
            MySocket.listen(1)

            #Ã©tablissement de la connexion
            connexion,addresse=MySocket.accept()
            print("S > Connexion client réussie, adresse IP %s, port %s \n" %(HOST,PORT))

            # dialogue avec le client, envoi du premier message
            #connexion.send(b'Connexion OK')
            print("S > Début du pseudoTLS handshake")
            

            #Etape 1: Reception Client Hello
            if connexion.recv(BUFFER)!=b'Client Hello':
                if connexion.recv(BUFFER)==b'FIN':
                    connexion.close()
                    MySocket.close()
                    print("S > Le client a mis fin à la connexion : probleme Hello")
                    sys.exit()
            else:
                #Etape 2: envoi Server Hello
                print("S > Client said : HELLO")
                connexion.send(b'Server Hello')
            
            time.sleep(0.5)
            #Etape 3: Server send public key
            connexion.send(public_key_server.exportKey('DER'))
            print("S > clef publique envoyée")



            #Etape 4: Envoi du hash de la clé publique
            connexion.send(hashlib.sha256(public_key_server.exportKey('DER')).hexdigest())
            print("S > Hash clef publique envoyé")

            
            #Etape 5: Server Hello Done
            connexion.send(b'Server Hello done')
            
            #Etape 6: Réception de la validation du certificat
            if connexion.recv(BUFFER)!=b'Certificat OK':
                print("S > Le certificat n'a pas été vérifié !")
                if connexion.recv(BUFFER)==b'Certificat NOK':
                    connexion.close()
                    MySocket.close()
                    print("S > Le client a mis fin à la connexion : probleme certificat")
                    sys.exit()
            else:
                print("S > Le certificat a été vérifié par le client.")

            #Etape 7: Réception de la clé AES
            encrypted_aes_key = connexion.recv(BUFFER)
            print("S > la clé a été ecue chiffree")
            aes_key = dechiffrement_RSA(encrypted_aes_key,private_key_server)
            print("S > la clé a été dechiffree")
            #Etape 8: Réception du hash de la CLE AES
            time.sleep(0.5)
            aes_hash = (connexion.recv(BUFFER))
            print("S > Le hash de la cle a ete recu chiffree")
            aes_hash = dechiffrement_RSA(aes_hash,private_key_server)
            #Etape 9: Envoi d'un AES KEY OK SERVER FINISHED

            if aes_hash != hashlib.sha256(aes_key).hexdigest():
                print("S > Le hash de la clé ne correspond pas")
                connexion.send(b'AES KEY NOK')
                if connexion.recv(BUFFER) == b'FIN':
                    connexion.close()
                    MySocket.close()
                    sys.exit()
            else:
                print("S > Le hash de la clé est valide")
                connexion.send(b'AES KEY OK SERVER FINISHED')
                print("S > pseudoTLS handshake est terminé")
                print("S > Debut de communication chiffrée")
            

            #Ensuite : communication
                # boucle d'échange avec le client
            while 1 :
                print("S > #### Debut de la boucle d'échange ####")
                msgClient=connexion.recv(BUFFER)
                testMessageClient=dechiffrement(msgClient.decode(),aes_key)
                if testMessageClient=="FIN" :
                    print("S > Fin de la connexion par le client")
                    break
                elif testMessageClient=="WAIT":
                    continue
                if testMessageClient=="TEST":
                    print("S > TEST COMMUNICATION OK")
                    msgServer = 'TEST OK'
                    msgServer = chiffrement(msgServer,aes_key)
                    connexion.send(msgServer)
                    print("S > Message de Test envoyé au client")
                if testMessageClient == "image":
                            
                            public_key_client = RSA.importKey(connexion.recv(BUFFER))
                            print(public_key_client)
                            connexion.send(public_key_server.exportKey('DER'))
                            #on rÃ©ceptionne la clÃ© pour dÃ©chiffrer
                            key=connexion.recv(BUFFER)
                            key = dechiffrement_RSA(key,private_key_server,public_key_client)
                            #on rÃ©ceptionne l'image
                            string_to_image(testMessageClient,connexion)
                            #on rÃ©cupÃ¨re le message chiffrÃ© et on le dÃ©chiffre
                            lire_code(key)
                            msgServer = ">>> De Serveur : Message bien reÃ§u"
                            msgServer = msgServer.encode()
                            print(">>> Envoi de la rÃ©ponse vers le client")
                            connexion.send(msgServer)
            
            # fermeture de la connexion
            connexion.send(b"FIN")
            print("S > connexion interompue par le client!!!!")
            connexion.close()           
    MySocket.close()