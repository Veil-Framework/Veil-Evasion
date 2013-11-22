"""

Automates the running the the Hyperion crypter on an existing .exe

More information (Nullsecurity) - http://www.nullsecurity.net/papers/nullsec-bsides-slides.pdf

"""

import sys, time, subprocess

from modules.common import randomizer
from modules.common import helpers

# the main config file
import settings

class Payload:
	
	def __init__(self):
		# required options
		self.description = "Automates the running of the Hyperion crypter on an existing .exe"
		self.language = "native"
		self.rating = "Normal"
		self.extension = "exe"

		# options we require user interaction for- format is {Option : [Value, Description]]}
		self.required_options = {"original_exe" : ["", "The executable to run Hyperion on"]}
		
	def generate(self):
		
		# randomize the output file so we don't overwrite anything
		randName = randomizer.randomString(5) + ".exe"
		outputFile = settings.TEMP_DIR + randName
		
		# the command to invoke hyperion. TODO: windows compatibility
		hyperionCommand = "wine hyperion.exe " + self.required_options["original_exe"][0] + " " + outputFile
		
		print helpers.color("\n[*] Running Hyperion on " + self.required_options["original_exe"][0] + "...")
		
		# be sure to set 'cwd' to the proper directory for hyperion so it properly runs
		p = subprocess.Popen(hyperionCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=settings.VEIL_PATH+"tools/hyperion/", shell=True)
		stdout, stderr = p.communicate()
		
		try:
			# read in the output .exe from /tmp/
			f = open(outputFile, 'rb')
			PayloadCode = f.read()
			f.close()
		except IOError:
			print "\nError during Hyperion execution:\n" + helpers.color(stdout, warning=True)
			raw_input("\n[>] Press any key to return to the main menu:")
			return ""
		
		# cleanup the temporary output file. TODO: windows compatibility
		p = subprocess.Popen("rm " + outputFile, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		stdout, stderr = p.communicate()

		return PayloadCode
