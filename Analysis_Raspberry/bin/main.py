# coding: utf8
#!/usr/bin/env python

import time
import socket
import sys
import getpass
import hashlib
import os
import imp
import binascii
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import randpool
from Crypto.Cipher import PKCS1_OAEP
from modules import rsa
from modules import aes
from modules import parseconf

file_path = os.path.dirname(os.path.realpath(__file__))
BUFFER = 2048

def string_to_image(encoded_string,connexion):
    fp = open("crypted_.png",'wb')
    while True:
        strng = connexion.recv(1024)
        if strng=="transfert fini".encode():
            break
        fp.write(strng)
        
    fp.close()
    print("Data received successfully")

if __name__ == '__main__':

    #Récupération des options présentes dans le fichier de configuration  
    configurations = parseconf.parse_configuration_file("../etc/Analysis_Sender.conf")

    #Génération de la paire de clé
    private_key_server = rsa.generate_key()
    public_key_server = private_key_server.publickey()
    
    #Création de la socket
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(configurations)
    HOST=configurations["ListeningIP"]
    PORT=int(configurations["IncomingPort"])


    testMessageClient=""

    #Création d'une socket avec la famille IP + TCP
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
            aes_key = rsa.decryption(encrypted_aes_key,private_key_server)
            print("S > la clé a été dechiffree")
            #Etape 8: Réception du hash de la CLE AES
            time.sleep(0.5)
            aes_hash = (connexion.recv(BUFFER))
            print("S > Le hash de la cle a ete recu chiffree")
            aes_hash = rsa.decryption(aes_hash,private_key_server)
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
                testMessageClient=aes.decryption(msgClient,aes_key)
                if testMessageClient=="FIN" :
                    print("S > Fin de la connexion par le client")
                    break
                elif testMessageClient=="WAIT":
                    continue
                if testMessageClient=="TEST":
                    print("S > TEST COMMUNICATION OK")
                    msgServer = 'TEST OK'
                    msgServer = aes.encryption(msgServer,aes_key)
                    connexion.send(msgServer)
                    print("S > Message de Test envoyé au client")
                if testMessageClient == "image":
                            
                            public_key_client = RSA.importKey(connexion.recv(BUFFER))
                            print(public_key_client)
                            connexion.send(public_key_server.exportKey('DER'))
                            #on rÃ©ceptionne la clÃ© pour dÃ©chiffrer
                            key=connexion.recv(BUFFER)
                            key = rsa.decryption(key,private_key_server,public_key_client)
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