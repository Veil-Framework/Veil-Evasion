"""

Automates the running the PEScrambler on an existing .exe

PEScrambler by Nick Harbour - http://code.google.com/p/pescrambler/

"""

import sys, time, subprocess, time, os

from modules.common import helpers

# the main config file
import settings

class Payload:

    def __init__(self):
        # required options
        self.description = "Automates the running of the PEScrambler crypter on an existing .exe"
        self.language = "native"
        self.rating = "Normal"
        self.extension = "exe"

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "ORIGINAL_EXE" : ["", "The executable to run PEScrambler on"]
                                }

    def generate(self):

        # randomize the output file so we don't overwrite anything
        randName = helpers.randomString(5) + ".exe"
        outputFile = settings.TEMP_DIR + randName

        # the command to invoke hyperion. TODO: windows compatibility
        if not os.path.isfile(self.required_options["ORIGINAL_EXE"][0]):
            print "\nError during PEScrambler execution:\nInput file does not exist"
            raw_input("\n[>] Press any key to return to the main menu.")
            return ""

        print helpers.color("\n[*] Running PEScrambler on " + self.required_options["ORIGINAL_EXE"][0] + "...")

        # be sure to set 'cwd' to the proper directory for hyperion so it properly runs
        p = subprocess.Popen(["wine", settings.VEIL_EVASION_PATH + "tools/pescrambler/PEScrambler.exe", "-i", self.required_options["ORIGINAL_EXE"][0], "-o", outputFile], cwd=settings.VEIL_EVASION_PATH+"tools/pescrambler/")
        time.sleep(7)
        stdout, stderr = p.communicate()

        try:
            # read in the output .exe from /tmp/
            f = open(outputFile, 'rb')
            PayloadCode = f.read()
            f.close()
            command2 = "rm " + outputFile
            p2 = subprocess.Popen(command2.split())
            stdout, stderr = p.communicate()
        except IOError:
            print "\nError during PEScrambler execution:\n" + helpers.color(stdout, warning=True)
            raw_input("\n[>] Press any key to return to the main menu.")
            return ""

        # cleanup the temporary output file. TODO: windows compatibility
        if os.path.isfile(outputFile):
            p = subprocess.Popen(["rm", outputFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout, stderr = p.communicate()

        return PayloadCode
