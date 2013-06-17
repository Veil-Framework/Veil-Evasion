#!/usr/bin/python

import platform, os, sys

"""

Take an options dictionary and update ./config/veil.py

"""
def generateConfig(options):
	
	config = """#!/usr/bin/python

##################################################################################################
#
# Veil configuration file												
#
# Run update.py to automatically set all these options.
#
##################################################################################################

"""

	config += '# OS to use (Kali/Backtrack/Debian/Windows)\n'
	config += 'OPERATING_SYSTEM="'+options['OPERATING_SYSTEM']+'"\n\n'
	
	config += '# Veil base install path\n'
	config += 'VEIL_PATH="'+options['VEIL_PATH']+'"\n\n'
	
	config += '# Path to output the source of payloads\n'
	config += 'PAYLOAD_SOURCE_PATH="'+options["PAYLOAD_SOURCE_PATH"]+'"\n\n'
	
	config += '# Path to output compiled payloads\n'
	config += 'PAYLOAD_COMPILED_PATH="'+options["PAYLOAD_COMPILED_PATH"]+'"\n\n'
	
	config += '# Path to temporary directory\n'
	config += 'TEMP_DIR="' + options["TEMP_DIR"] + '"\n\n'
	
	config += '# The path to the metasploit framework, for example: /usr/share/metasploit-framework/\n'
	config += 'METASPLOIT_PATH="'+options['METASPLOIT_PATH']+'"\n\n'
	
	f = open("veil.py", 'w')
	f.write(config)
	f.close()
	
	# create the output directories if they don't exist
	if not os.path.exists(options["PAYLOAD_SOURCE_PATH"] ): 
		os.makedirs(options["PAYLOAD_SOURCE_PATH"] )
		print " [*] " + options["PAYLOAD_SOURCE_PATH"] + " created"
	
	if not os.path.exists(options["PAYLOAD_COMPILED_PATH"] ): 
		os.makedirs(options["PAYLOAD_COMPILED_PATH"] )
		print " [*] " + options["PAYLOAD_COMPILED_PATH"] + " created"
	
	print " [*] Configuration file successfully written to 'veil.py'\n"


if __name__ == '__main__':

	options = {}

	if platform.system() == "Linux":
		
		# check /etc/issue for the exact linux distro
		issue = open("/etc/issue").read()
		
		if issue.startswith("Kali"):
			print " [*] OPERATING_SYSTEM = Kali"
			
			options["OPERATING_SYSTEM"] = "Kali"
			options["METASPLOIT_PATH"] = "/usr/share/metasploit-framework/"
			print " [*] METASPLOIT_PATH = /usr/share/metasploit-framework/"
			
		elif issue.startswith("BackTrack"):
			print " [*] OPERATING_SYSTEM = BackTrack"
			options["OPERATING_SYSTEM"] = "BackTrack"
			options["METASPLOIT_PATH"] = "/opt/metasploit/msf3/"
			print " [*] METASPLOIT_PATH = /opt/metasploit/msf3/"
			
		else:
			print " [*] OPERATING_SYSTEM = Linux"
			options["OPERATING_SYSTEM"] = "Linux"
			
			msfpath = raw_input(" [>] Please enter the path of your metasploit installation: ")
			options["METASPLOIT_PATH"] = msfpath
		
		veil_path = "/".join(os.getcwd().split("/")[:-1]) + "/"
		options["VEIL_PATH"] = veil_path
		print " [*] VEIL_PATH = " + veil_path
		
		options["PAYLOAD_SOURCE_PATH"] = veil_path + "output/source/"
		print " [*] PAYLOAD_SOURCE_PATH = " + veil_path + "output/source/"
		options["PAYLOAD_COMPILED_PATH"] = veil_path + "output/compiled/"
		print " [*] PAYLOAD_COMPILED_PATH = " + veil_path + "output/compiled/"
		
		options["TEMP_DIR"]="/tmp/"
		print " [*] TEMP_DIR = /tmp/"
		
	# not current supported
	elif platform.system() == "Windows":
		print " [*] OPERATING_SYSTEM = Windows"
		options["OPERATING_SYSTEM"] = "Windows"

		veil_path = "\\".join(os.getcwd().split("\\")[:-1]) + "\\"
		options["VEIL_PATH"] = veil_path
		print " [*] VEIL_PATH = " + veil_path
		
		options["PAYLOAD_SOURCE_PATH"] = veil_path + "output\\source\\"
		print " [*] PAYLOAD_SOURCE_PATH = " + veil_path + "output\\source\\"
		options["PAYLOAD_COMPILED_PATH"] = veil_path + "output\\compiled\\"
		print " [*] PAYLOAD_COMPILED_PATH = " + veil_path + "output\\compiled\\"
		
		options["TEMP_DIR"]="C:\\Windows\\Temp\\"
		print " [*] TEMP_DIR = C:\\Windows\\Temp\\"
		
		msfpath = raw_input(" [>] Please enter the path of your metasploit installation: ")
		options["METASPLOIT_PATH"] = msfpath
	
	# unsupported platform... 
	else:
		print " [!] ERROR: PLATFORM NOT SUPPORTED"
		sys.exit()

	generateConfig(options)
