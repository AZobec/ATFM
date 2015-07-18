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

file_path = os.path.dirname(os.path.realpath(__file__))

if __name__ == '__main__':

    #Récupération des options présentes dans le fichier de configuration  
    configurations = parseconf.parse_configuration_file("../etc/Analysis_Sender.conf")
    #communication.with_honeypot(configurations)
    FIR.create_event(configurations)
    