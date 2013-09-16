"""

Description of the payload.


Addtional notes, sources, links, etc.


Author of the module.

"""

# any necessary framework/other imports
from modules.common import shellcode

# the main config file
import settings

class Stager:
	
	def __init__(self):
		# required options
		self.shortname = "VirtualAllocLolz"
		self.description = "description"
		self.language = "python/cs/powershell/whatever"
		self.rating = "Poor/Normal/Good/Excellent"
		self.extension = "py/cs/c/etc."
		
		self.shellcode = shellcode.Shellcode()
		# options we require user ineraction for- format is {Option : [Value, Description]]}
		# the code logic will parse any of these out and require the user to input a value for them
		self.required_options = {
						"compile_to_exe" : ["Y", "Compile to an executable"],
						"use_pyherion" : ["N", "Use the pyherion encrypter"]}
		self.notes = "...additional notes to user..."

	# main method that returns the generated payload code
	def generate(self):
		
		# Generate Shellcode Using msfvenom
		Shellcode = self.shellcode.generate()
		
		PayloadCode = "..."
		
		# example of how to	check the internal options
		if self.required_options["use_pyherion"][0].lower() == "y":
			PayloadCode = crypters.pyherion(PayloadCode)

		return PayloadCode
