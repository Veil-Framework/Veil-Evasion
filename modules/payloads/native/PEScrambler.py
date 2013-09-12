"""

Automates the running the PEScrambler on an existing .exe

PEScrambler by Nick Harbour - http://code.google.com/p/pescrambler/

"""

import sys, time, subprocess, time

from modules.common import randomizer
from modules.common import helpers

# the main config file
import settings

class Stager:
	
	def __init__(self):
		# required options
		self.shortname = "pescrambler"
		self.description = "Automates the running of the PEScrambler crypter on an existing .exe"
		self.language = "native"
		self.rating = "Normal"
		self.extension = "exe"

		# options we require user interaction for- format is {Option : [Value, Description]]}
		self.required_options = {"original_exe" : ["", "The executable to run PEScrambler on"]}
		
	def generate(self):
		
		# randomize the output file so we don't overwrite anything
		randName = randomizer.randomString(5) + ".exe"
		outputFile = settings.TEMP_DIR + randName
		
		# the command to invoke hyperion. TODO: windows compatibility
		peCommand = "wine PEScrambler.exe -i " + self.required_options["original_exe"][0] + " -o " + outputFile

		print helpers.color("\n[*] Running PEScrambler on " + self.required_options["original_exe"][0] + "...")
		
		# be sure to set 'cwd' to the proper directory for hyperion so it properly runs
		p = subprocess.Popen(peCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=veil.VEIL_PATH+"tools/pescrambler/", shell=True)
		time.sleep(3)
		stdout, stderr = p.communicate()
		
		try:
			# read in the output .exe from /tmp/
			f = open(outputFile, 'rb')
			PayloadCode = f.read()
			f.close()
		except IOError:
			print "\nError during PEScrambler execution:\n" + helpers.color(stdout, warning=True)
			raw_input("\n[>] Press any key to return to the main menu:")
			return ""
		
		# cleanup the temporary output file. TODO: windows compatibility
		p = subprocess.Popen("rm " + outputFile, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		stdout, stderr = p.communicate()

		return PayloadCode
