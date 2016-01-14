#!/usr/bin/env python

"""
Front end launcher for the Veil AV-evasion framework.

Handles command line switches for all options.
A modules.commoncontroller.Controller() object is instantiated with the
appropriate switches, or the interactive menu is triggered if no switches
are provided.
"""

# Import Modules
import sys, argparse, time, os, base64, socket

from modules.common import controller
from modules.common import messages
from modules.common import supportfiles
from modules.common import helpers

def runRPC(port=4242):
    '''
    REST API is entirely JSON based, both requests and respoonses. The following is the format:

    version:
        request => {'action': 'version'}
        response <= {'version': <version info>}

    module options:
        request => {'action': 'options', 'name': '<module name>'}
        response <= {<Dict: <option key> => <optiion value>}

    generate:
        requests => {'action': 'generate', 'payload': {Dict: <option key> => <option value}}
        response <= {'path': '<path to binar>'}

    if there is an error processing the request, the response will be:
        {'error': '<some error message>'}
    '''
    from flask import Flask
    from flask import request
    import json

    app = Flask(__name__)
    con = controller.Controller(oneRun=False)

    def generate_payload(payload, filename, options, overwrite=True, pwnstaller=False):
        con.SetPayload(payload, options)
        code = con.GeneratePayload()

        class Args(object):
            pass

        args = Args()
        args.overwrite = overwrite
        args.o = filename
        args.pwnstaller = pwnstaller

        output = con.OutputMenu(con.payload, code, showTitle=False, interactive=False, args=args)
        return json.dumps({'path': output})


    @app.errorhandler(Exception)
    def exception_handler(error):
        return repr(error)

    @app.route('/', methods=['GET', 'POST'])
    def index():
        data = json.loads(request.data)

        if data['action'] == 'version' or request.method == 'GET':
            return json.dumps({'version': 'Veil-Evasion RPC Server %s' % messages.version})

        elif data['action'] == 'payloads':
            return json.dumps([name for (name, payload) in con.payloads])

        elif data['action'] == 'options':
            p = [payload for (payloadname, payload) in con.payloads if data['name'].lower() == payloadname.lower()]

            if len(p) != 1:
                raise 'Error getting payload with name: %s' % name

            if hasattr(p[0], 'required_options'):
                return json.dumps(p[0].required_options)

            raise 'No payload options found for name: %s' % name

        elif data['action'] == 'generate':
            opts = data['options']

            if 'outputbase' not in opts:
                return json.dumps({'error': 'generated requires a outputbase to specified'})

            ow = opts['overwrite'] if 'overwrite' in opts else True
            pi = opts['pwnstaller'] if 'pwnstaller' in opts else False

            if 'payload' in opts:
                if 'LHOST' not in opts:
                    return json.dumps({'error': 'generated requires a lhost to specified'})

                p = [payload for (payloadname, payload) in con.payloads if opts['payload'].lower() == payloadname.lower()]

                if len(p) != 1:
                    raise 'Error getting payload with name: %s' % name

                o = {}
                o['required_options'] = {r: [opts[r], ''] for r in p[0].required_options.iterkeys() if r in opts}

                return generate_payload(opts['payload'], opts['outputbase'], o, ow, pi)

            if 'shellcode' in opts:
                o = {}
                o['customShellcode'] = opts['shellcode']
                return generate_payload(opts['payload'], opts['outputbase'], o, ow, pi)

            if 'msfpayload' in opts or 'msfvenom' in opts:
                name = opts['msfpayload'] if 'msfpayload' in opts else opts['msfvenom']
                o = {}
                o['msfvenom'] = [name, ','.join(['"%s=%s"' % (k,v) for (k,v) in opts.iteritems()])]
                return generate_payload(opts['payload'], opts['outputbase'], o, ow, pi)

            return json.dumps({'error': 'there was an error in your generate parameters'})

        return json.dumps(data)

    print ' * Starting Veil-Evasion RPC server'
    app.run(port=port)

if __name__ == '__main__':
    try:
        # keep Veil.pyc from appearing?
        sys.dont_write_bytecode = True

        parser = argparse.ArgumentParser()
        parser.add_argument('-c', metavar='OPTION1=value OPTION2=value', nargs='*', help='Custom payload module options.')
        parser.add_argument('-o', metavar="OUTPUTBASE", default="payload", help='Output file base for source and compiled binaries.')
        parser.add_argument('-p', metavar="PAYLOAD", nargs='?', const="list", help='Payload to generate. Lists payloads if none specified.')
        #parser.add_argument('-v', action="store_true", help='More detailed output.')
        parser.add_argument('--clean', action='store_true', help='Clean out payload folders.')
        #parser.add_argument('--custshell', metavar="\\x00...", help='Custom shellcode string to use.')
        parser.add_argument('--msfoptions', metavar="OPTION=value", nargs='*', help='Options for the specified metasploit payload.')
        parser.add_argument('--msfvenom', metavar="windows/meterpreter/reverse_tcp", nargs='?', help='Metasploit shellcode to generate.')
        parser.add_argument('--overwrite', action='store_true', help='Overwrite payload/source output files if they already exist.')
        parser.add_argument('--pwnstaller', action='store_true', help='Use the Pwnstaller obfuscated loader.')
        parser.add_argument('--rpc', action='store_true', help='Run Veil-Evasion as an RPC server.')
        parser.add_argument('--update', action='store_true', help='Update the Veil framework.')
        parser.add_argument('--version', action="store_true", help='Displays version and quits.')

        args = parser.parse_args()

        # Print version
        if args.version:
            messages.title()
            sys.exit()

        # start up the RPC server
        if args.rpc:
            runRPC()
            sys.exit()

        # Print main title
        messages.title()

        # instantiate the main controller object
        controller = controller.Controller(oneRun=False)

        # call the update functionality for Veil and then exit
        if args.update:
            controller.UpdateVeil(interactive=False)
            sys.exit()

        # call the payload folder cleaning for Veil and then exit
        if args.clean:
            controller.CleanPayloads(interactive=False)
            sys.exit()

        # use interactive menu if a payload isn't specified
        if not args.p:
            controller.MainMenu(args=args)
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
                options['required_options'][name.upper()] = [value, ""]

        # pull out any msfvenom shellcode specification and msfvenom options
        if args.msfvenom:
            if args.msfoptions:
                options['msfvenom'] = [args.msfvenom, args.msfoptions]
            else:
                options['msfvenom'] = [args.msfvenom, None]

        # manually set the payload in the controller object
        controller.SetPayload(args.p, options)

        # generate the payload code
        code = controller.GeneratePayload()

        # write out the payload code to the proper output file
        outName = controller.OutputMenu(controller.payload, code, showTitle=False, interactive=False, args=args)

    # Catch ctrl + c interrupts from the user
    except KeyboardInterrupt:
        print helpers.color("\n\n [!] Exiting...\n", warning=True)

    except EOFError:
        print helpers.color("\n\n [!] Exiting...\n", warning=True)
