# coding: utf8
#!/usr/bin/env python

from lxml import etree

def honeypot_proofs(configurations,proof_file):
	tree = etree.parse(configurations["DataLocation"]+proof_file)
	for preuve in tree.xpath("/preuves/preuve"):
		
		if preuve.get("type") == "tentative de connexion":
			print("###### Preuve ######")
			print("IP :"+preuve.find("ip").text)
			print("PORT:"+preuve.find("port").text)
			print("Data:"+preuve.find("data").text)

#ID  for THREATINTEL is 18