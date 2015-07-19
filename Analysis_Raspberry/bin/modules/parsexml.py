# coding: utf8
#!/usr/bin/env python

from lxml import etree
from time import strftime 
from modules import FIR


def honeypot_proofs(configurations,proof_file):
	tree = etree.parse(configurations["DataLocation"]+proof_file)
	for preuve in tree.xpath("/rapport/preuves/preuve"):
		
		#Test ?
		#if preuve.get("type") == "tentative de connexion":
		#	print("###### Preuve ######")
		#	print("IP :"+preuve.find("ip").text)
		#	print("PORT:"+preuve.find("port").text)
		#	print("Data:"+preuve.find("data").text)

		#'18/07/2015 16:01:04'
		date = strftime("%d/%m/%Y %H:%M:%S")
		print ("Date: "+date)
			#IF NIVEAU 3 : ON ENVOIE
		if preuve.find("score").text == "3":
			datas = {'csrfmiddlewaretoken' : 'JrDSAkAfHh5kwA7UERzchoDI0RVR10pZ',
			        'subject' : preuve.get("type"),
			        'category' : '18',
			        'status' : 'O',
			        'detection' : '2',
			        'severity' : '2',
			        'date' : date,
			        'actor' : '',
			        'plan' : '',
			        'confidentiality' : '1',
			        'description' : "<p>DATAS : <p><p>"+preuve.find("data").text+"</p>",
			        }
			print("Preuve niveau 3 :!!")
			print ("on affiche :")
			FIR.create_event_from_xml(configurations,datas)

			#IF NIVEAU 4 : ON ENVOIE AUSSI


#ID  for THREATINTEL is 18