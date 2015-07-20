# coding: utf8
#!/usr/bin/env python

from os import listdir
from os.path import isfile, join
from modules import parsexml

def bash_history(configurations,file_name):
	bash_history = open(configurations["DataLocation"]+file_name,"rb")
	t = bash_history.read()
	print(t)
	if t != "":
		proof_bash=dict(type = "ioc", ip = configurations["ListeningIP"], port = "none", data = t, score = "3")
		parsexml.add_proof(configurations,"proofs.xml",proof_bash)
		#ip 
		#port 
		#datas 
		#score