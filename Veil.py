#!/usr/bin/python

"""
Front end launcher for the Veil AV-evasion framework.

Handles command line switches for all options.
A modules.commoncontroller.Controller() object is instantiated with the
appropriate switches, or the interactive menu is triggered if no switches
are provided.
"""

# Import Modules
import sys
import argparse
import time

from modules.common import controller
from modules.common import messages
from modules.common import supportfiles
from modules.common import helpers

if __name__ == '__main__':
    try:
        # keep Veil.pyc from appearing?
        sys.dont_write_bytecode = True

        parser = argparse.ArgumentParser()
        parser.add_argument('-p', metavar="PAYLOAD", nargs='?', const="list", help='Payload to generate. Lists payloads if none specified.')
        parser.add_argument('-c', metavar='OPTION=value', nargs='*', help='Custom payload module options.')
        parser.add_argument('-o', metavar="OUTPUTBASE", default="payload", help='Output file base for source and compiled .exes.')
        parser.add_argument('--msfpayload', metavar="windows/meterpreter/reverse_tcp", nargs='?', help='Metasploit shellcode to generate.')
        parser.add_argument('--msfoptions', metavar="OPTION=value", nargs='*', help='Options for the specified metasploit payload.')
        parser.add_argument('--custshell', metavar="\\x00...", help='Custom shellcode string to use.')
        parser.add_argument('--update', action='store_true', help='Update the Veil framework.')
        args = parser.parse_args()

        # Print main title
        messages.title()

        # instantiate the main controller object
        controller = controller.Controller(oneRun=False)

        # call the update functionality for Veil and then exit
        if args.update:
            controller.UpdateVeil(interactive=False)
            sys.exit()

        # use interactive menu if a payload isn't specified
        if not args.p:
            controller.MainMenu()
            sys.exit()

        # list languages available if "-p" is present but no payload specified
        elif args.p == "list":
            controller.ListPayloads()
            sys.exit()
        
        # pull out any required options from the command line and
        # build the proper dictionary so we can set the payload manually
        options = {}
        if args.c:
            options['required_options'] = {}
            for option in args.c:
                name,value = option.split("=")
                options['required_options'][name] = [value, ""]

        # pull out any msfvenom shellcode specification and msfvenom options
        if args.msfpayload:
            if args.msfoptions:
                options['msfvenom'] = [args.msfpayload, args.msfoptions]
            else:
                options['msfvenom'] = [args.msfpayload, None]

        # manually set the payload in the controller object
        controller.SetPayload(args.p, options)

        # generate the payload code
        code = controller.GeneratePayload()

        # write out the payload code to the proper output file
        outName = controller.OutputMenu(controller.payload, code, showTitle=False, interactive=False, OutputBaseChoice=args.o)


    # Catch ctrl + c interrupts from the user
    except KeyboardInterrupt:
        print helpers.color("\n\n [!] Exiting...\n", warning=True)

