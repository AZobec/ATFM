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
from os import listdir
from os.path import isfile, join

BUFFER = 2048

def receive_file(encoded_string,connexion):
    fp = open("crypted_.png",'wb')
    while True:
        strng = connexion.recv(1024)
        if strng=="transfert fini".encode():
            break
        fp.write(strng)
        
    fp.close()

def send_file(socket,_file_):
    #On va ouvrir le fichier et l'envoyer directement bit par bit
    file_ = open(_file_,'rb')
    
    while True:
        strng = file_.readline()
        if not strng:
            break
        socket.send(strng)
        
    file_.close()
    time.sleep(0.5)
    socket.send("transfert fini".encode())
    print(">>> Data transfered successfully")

def with_analysis(configurations):
 #Generating RSA keys....
    private_key_client = rsa.generate_key()
    public_key_client = private_key_client.publickey()

    #Creating the socket
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    HOST=configurations["DestinationIP"]
    PORT=int(configurations["DestinationPort"])

    try:
            #Connect to the server, watched block, exceptions are managed
            sock.connect((HOST,PORT))
    except socket.error:
            print(">>> La connexion a échouée...")
            sys.exit()
    print(">>> Connexion établie avec le serveur...")

    print(">>> Début du TLS Handhake...")
    
    #Sted 1: Send Client Hello to server
    sock.send(b'Client Hello')

    #Step 2: Receive Server Hello from server      
    if sock.recv(BUFFER)!= b'Server Hello':
            print(">>> Problème TCP : Server Hello : FAILED")
            sock.send(b'FIN')
            sock.close()
            sys.exit()
     #Else Server Hello                
    else:
            print(">>> Server said : HELLO")
            #Step 3: receive public key
            time.sleep(0.5)
            public_key_server = RSA.importKey(sock.recv(BUFFER))

            print(">>> Réception de la clé publique")
            #Step 4: receive public key's hash
            hash_public_key_server = sock.recv(BUFFER)
            print(">>> Clé publique reçue")        
    #Compare hashs after the end of Server Hello
    #Step 5: Receive Server Hello Done
    if sock.recv(BUFFER)!=b'Server Hello done':
            print(">>> Problème TCP : Server Hello Done : FAILED")
            sock.send(b'FIN')
            sock.close()
            sys.exit()
    else:
            #Step 6: Send certificat validation(ok ou nok)
            if hash_public_key_server.decode()==hashlib.sha256(public_key_server.exportKey('DER')).hexdigest():
                    print("LE HASH EST OK")
                    sock.send(b'Certificat OK')
                    print(">>> Le certificat a été \"vérifié\"")

            #Else validation certificat
            else:
                    print(">>> Problème PublicKey : LA CLE NE CORRESPOND PAS AU HASH")
                    sock.send(b'Certificat NOK')
                    sock.close()
                    sys.exit()

    #Step 7: Envoi de la clé AES
    aes_key = os.urandom(32)
    encrypted_aes_key = rsa.encryption(aes_key,public_key_server)
    print(">>> La clé a été chiffrée")
    #Envoi de la clé
    sock.send(encrypted_aes_key)
    print(">>> La clé a été envoyée au serveur")
    #Step 8: Envoi du hash et vérification de la clé de chiffrement
    #Step 8: send hash and verify AES KEY
    #Le hash est lui aussi chiffré via RSA
    #Hash is encrypted with RSA too
    hash_aes_key = hashlib.sha256(aes_key).hexdigest()
    hash_aes_key = rsa.encryption(hash_aes_key,public_key_server)
    time.sleep(0.5)
    sock.send(hash_aes_key)

    #Step 9: vérification de la clé par retour de OK server sur le hash
    #Step 9: key verified by OK returned by the server on the hash check
    if sock.recv(BUFFER)!=b'AES KEY OK SERVER FINISHED':
            sock.send(b'FIN')
            sock.close()
            sys.exit()
    else:
            print(">>> Le Server a terminé le pseudoTLS Handshake")
            print(">>> Début de la communication chiffrée")
    #on a la boucle de communication habituelle

     #Ce qu'on veut faire : prendre touis les fichiers dans un répertoire, et les envoyer
    for data_file in listdir(configurations["DataLocation"]):
        if isfile(join(configurations["DataLocation"],data_file)):
            if not ".enc" in data_file:
                #là on est sûr qie c'est un file dans les DataLocation
                time.sleep(5)
                # 1 : on chiffre le fichier
                aes.encrypt_file(aes_key, configurations["DataLocation"]+"/"+data_file)
                print("Fichier chiffré")
                try:
                    aes.decrypt_file(aes_key, configurations["DataLocation"]+"/"+data_file+".enc")
                    print("Fichier OK pour le déchiffrement")
                except:
                    print("Fichier NOK pour le déchiffrement")
                toclientmessage = aes.encryption("Incoming_file",aes_key)
                sock.send(toclientmessage)
                time.sleep(0.5)
                # 2 : on envoie le nom du fichier
                toclientmessage = aes.encryption(data_file+".enc",aes_key)
                sock.send(toclientmessage)
                time.sleep(0.5)
                send_file(sock,configurations["DataLocation"]+"/"+data_file+".enc")
                time.sleep(1)
                ############## TOOOOO FINIIIIISH ##############

    toclientmessage = aes.encryption("FIN_COMMUNICATION",aes_key)
    sock.send(toclientmessage)
    print (">>> Connexion interrompue proprement par le serveur")
    sock.close()
    sys.exit()
