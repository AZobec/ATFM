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
from modules import communication
from modules import FIR
from modules import parsexml
from modules import parseioc
from os import listdir
from os.path import isfile, join

file_path = os.path.dirname(os.path.realpath(__file__))

if __name__ == '__main__':

    #Récupération des options présentes dans le fichier de configuration  
    configurations = parseconf.parse_configuration_file("../etc/Analysis_Sender.conf")
    
    #On récupère les fichiers
    communication.with_honeypot(configurations)
    #On parse les datas et on en créé des events
    try:
        #parseioc.bash_history(configurations,"bash_history.ioc")
    except:
        print("S > Pas de fichier bash_history")
    try :
        #parseioc.bash_history(configurations,"bash_history_root.ioc")
    except:
        print("S > Pas de fichier bash_history_root")
    try:
        parseioc.w_ioc(configurations,"w.ioc")
    except :
        print("S > Pas de fichier w.ioc")
        print(configurations["DataLocation"]+"w.ioc")
    parsexml.honeypot_proofs(configurations,"proofs.xml")

    exit(0)
