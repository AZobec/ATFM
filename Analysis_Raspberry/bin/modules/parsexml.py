# coding: utf8
#!/usr/bin/env python

from lxml import etree

def honeypot_proofs(configurations,proof_file):
	tree = etree.parse(configurations["DataLocation"]+proof_file)
	for preuve in tree.xpath("/rapport/preuves/preuve"):
		
		if preuve.get("type") == "tentative de connexion":
			print("###### Preuve ######")
			print("IP :"+preuve.find("ip").text)
			print("PORT:"+preuve.find("port").text)
			print("Data:"+preuve.find("data").text)

			#IF NIVEAU 3 : ON ENVOIE
			if preuve.find("score").text == "3":
				print("Preuve niveau 3 :!!")

			#IF NIVEAU 4 : ON ENVOIE AUSSI


#ID  for THREATINTEL is 18