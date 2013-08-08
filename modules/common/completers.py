"""

Contains any classes used for tab completion.


Reference - http://stackoverflow.com/questions/5637124/tab-completion-in-pythons-raw-input

"""

# Import Modules
import readline
import commands
import re
import commands
import os


class MainMenuCompleter(object):
    """
    Class used for tab completion of the main Controller menu

    Takes a list of available commands, and loaded payload modules.

    """
    def __init__(self, cmds, payloads):
        self.commands = cmds
        self.payloads = payloads

    def complete_list(self, args):
        """List the languages you can list"""

        langs = ["all", "langs", "payloads"]
        for (name, payload) in self.payloads:
            langs.append(payload.language)
        langs = list(set(langs))

        if len(args) < 2:
            res = [ l + ' ' for l in langs if l.startswith(args[0])] + [None]
        # restrict infinite completion
        else:
            res = []

        return res

    def complete_use(self, args):
        """Complete payload/module"""

        res = []

        langs = []
        for (name, payload) in self.payloads:
            langs.append(payload.language)
        langs = list(set(langs))

        # if we're printing the language
        if len(args[0].split("/")) == 1:
            res = [ l + '/' for l in langs if l.startswith(args[0])] + [None]
        # if we're printing the payload
        else:

            lang,part = args[0].split("/")
            payloads = []
            for (name, payload) in self.payloads:
                if payload.language == lang:
                    payloads.append(payload.shortname)
                res = [ lang + '/' + p + ' ' for p in payloads if p.startswith(part)] + [None]

        return res

    def complete_info(self, args):
        """Complete payload/module"""

        res = []

        langs = []
        for (name, payload) in self.payloads:
            langs.append(payload.language)
        langs = list(set(langs))

        # if we're printing the language
        if len(args[0].split("/")) == 1:
            res = [ l + '/' for l in langs if l.startswith(args[0])] + [None]
        # if we're printing the payload
        else:

            lang,part = args[0].split("/")
            payloads = []
            for (name, payload) in self.payloads:
                if payload.language == lang:
                    payloads.append(payload.shortname)
                res = [ lang + '/' + p + ' ' for p in payloads if p.startswith(part)] + [None]

        return res


    def complete(self, text, state):

        "Generic readline completion entry point."
        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        # show all commands
        if not line:
            return [c + ' ' for c in self.commands][state]

        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')

        # resolve command to the implementation functions (above)
        cmd = line[0].strip()
        if cmd in self.commands:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]

        results = [ c + ' ' for c in self.commands if c.startswith(cmd)] + [None]

        return results[state]


class PayloadCompleter(object):

    def __init__(self, payload):
        self.payload = payload
        """self.commands = {"set":"set a specific option value",
                        "info":"show information about the payload",
                        "help":"show help menu for payload",
                        "back":"go to the main menu",
                        "generate":"generate payload"}"""
        self.commands = {"set":"set a specific option value",
                        "info":"show information about the payload",
                        "help [crypters]":"show help menu for payload or crypters",
                        "generate":"generate payload",
                        "back":"go to the main menu",
                        "exit":"exit Veil"}

    def complete_set(self, args):
        """List the options you can set"""

        res = []

        if hasattr(self.payload, 'required_options'):

            options = [k for k in sorted(self.payload.required_options.iterkeys())]

            if args[0] != "":
                if args[0].strip() == "LHOST":
                    res = [commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]] + [None]
                else:
                    # if there's a space at the end, return nothing
                    # otherwise, return a completion of the set command
                    if args[0][-1] != " ":
                        res = [ o + ' ' for o in options if o.startswith(args[0])] + [None]

        return res


    def complete(self, text, state):

        "Generic readline completion entry point."
        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        # show all commands
        if not line:
            return [c + ' ' for c in self.commands][state]

        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')

        # resolve command to the implementation functions (above)
        cmd = line[0].strip()
        if cmd in self.commands:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]

        results = [ c + ' ' for c in self.commands if c.startswith(cmd)] + [None]

        return results[state]


class MSFCompleter(object):
    """
    Class used for tab completion of metasploit payload selection.
    Used in ./modules/common/shellcode.py

    Takes a payloadTree next dictionary as an instantiation argument, of the form
        payloadTree = {"windows" : {"meterpreter", "shell",...}, "linux" : {...}}

    """
    def __init__(self, payloadTree):
        self.payloadTree = payloadTree


    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        # extract available platforms from the payload tree
        platforms = [k for k,v in self.payloadTree.items()]

        # show all platforms
        if not line:
            return [p + '/' for p in platforms][state]

        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')

        i = line[0].strip()

        # complete the platform
        if len(i.split("/")) == 1:
            results = [p + '/' for p in platforms if p.startswith(i)] + [None]
            return results[state]

        # complete the stage, including singles (no /)
        elif len(i.split("/")) == 2:
            platform = i.split("/")[0]
            stage = i.split("/")[1]
            stages = [ k for  k,v in self.payloadTree[platform].items()]
            results = [platform + "/" + s + '/' for s in stages if s.startswith(stage) and type(self.payloadTree[platform][s]) is dict]
            singles = [platform + "/" + s + ' ' for s in stages if s.startswith(stage) and type(self.payloadTree[platform][s]) is not dict]
            results += singles + [None]
            return results[state]

        # complete the stage (for x64) or stager (for x86)
        elif len(i.split("/")) == 3:

            platform = i.split("/")[0]
            stage = i.split("/")[1]
            stager = i.split("/")[2]

            stagers = [k for k,v in self.payloadTree[platform][stage].items()]

            results = [platform + "/" + stage + '/' + s + '/' for s in stagers if s.startswith(stager) and type(self.payloadTree[platform][stage][s]) is dict]
            singles = [platform + "/" + stage + '/' + s + ' ' for s in stagers if s.startswith(stager) and type(self.payloadTree[platform][stage][s]) is not dict]
            results += singles + [None]

            return results[state]

        # complete the stager for x64 (i.e. reverse_tcp)
        elif len(i.split("/")) == 4:

            platform = i.split("/")[0]
            arch = i.split("/")[1]
            stage = i.split("/")[2]
            stager = i.split("/")[3]

            stagers = [k for k,v in self.payloadTree[platform][arch][stage].items()]

            results = [platform + "/" + arch + "/" + stage + '/' + s for s in stagers if s.startswith(stager)] + [None]
            return results[state]

        else:
            return ""


class IPCompleter(object):
    """
    Class used for tab completion of local IP for LHOST.

    """
    def __init__(self):
        pass

    """
    If blank line, fill in the local IP
    """
    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        if not line:
            ip = [commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]] + [None]
            return ip[state]
        else:
            return text[state]


class MSFPortCompleter(object):
    """
    Class used for tab completion of the default port (4444) for MSF payloads

    """
    def __init__(self):
        pass

    """
    If blank line, fill in 4444
    """
    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        if not line:
            port = ["4444"] + [None]
            return port[state]
        else:
            return text[state]


class PathCompleter(object):
    """
    Class used for tab completion of files on the local path.
    """
    def __init__(self):
        pass

    def _listdir(self, root):
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
                for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_path(self, args):
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        return (self.complete_path(line) + [None])[state]
