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



if __name__ == '__main__':
    
    #Get .conf file datas  
    configurations = parseconf.parse_configuration_file("../etc/HoneypotSender.conf")
    communication.with_analysis(configurations)
   