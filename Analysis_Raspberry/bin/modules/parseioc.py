# coding: utf8
#!/usr/bin/env python

from os import listdir
from os.path import isfile, join
from modules import parsexml

def bash_history(configurations,file_name):
	bash_history = open(configurations["DataLocation"]+file_name,"rb")
	t = bash_history.read()
	if t != "":
		proof_bash=dict(type = "ioc", ip = configurations["ListeningIP"], port = "none", data = t, score = "3", name ="bash_history.ioc")
		parsexml.add_proof(configurations,"proofs.xml",proof_bash)
		#ip 
		#port 
		#datas 
		#score
	bash_history.close()

def w_ioc(configurations,file_name):
	w_ioc = open(configurations["DataLocation"]+file_name,"rb")
	count = 0
	proof = ""
	for line in w_ioc.readlines():
		if count == 0:
			if "users" in line:
				proof = "ALERT"
			count = count +1
	w_ioc.close()
	
	if proof == "ALERT":
		w_ioc = open(configurations["DataLocation"]+file_name,"rb")
		w_ioc_t = w_ioc.read()
		proof_w = dict(type = "ioc", ip = configurations["ListeningIP"], port = "none", data = w_ioc_t, score = "3", name = "w.ioc")
		parsexml.add_proof(configurations,"proofs.xml",proof_w)
		w_ioc.close()

def last(configurations,file_name):
	last = open(configurations["DataLocation"]+file_name,"rb")
	proof = ""
	for line in last.readlines():
		if "root" in line:
			proof = "ALERT"
	last.close()
	last = open(configurations["DataLocation"]+file_name,"rb")
	last_t = last.read()
	proof_last = dict(type = "ioc", ip = configurations["ListeningIP"], port = "none", data = last_t, score = "3", name = "last.ioc")
	parsexml.add_proof(configurations,"proofs.xml",proof_last)
	last.close()