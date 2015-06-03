# coding: utf8
#!/usr/bin/env python

def parse_configuration_file(config_file):
	#Dictionnary Creation
	configurations = dict()

	#Parsing the .conf into the dictionnary previously created
	conf_file = open(config_file, "r")
	
	for line  in conf_file:
		if line[0]!='#':
			if "=" in line:
				option, value= line.split('=',1)
				configurations[option[:-1]]=value[:-2]
			
	#Close the configuration file
	conf_file.close()
	return configurations
	
if __name__ == '__main__':
	configurations = parse_configuration_file("../../etc/HoneypotSender.conf")
	print(configurations)