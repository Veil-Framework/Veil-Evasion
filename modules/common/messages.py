"""
Common terminal messages used across the framework.
"""

import os, sys, types

import settings
from modules.common import helpers

def title():
    """
    Print the framework title, with version.
    """
    os.system(settings.TERMINAL_CLEAR)
    print '========================================================================='
    print ' Veil-Evasion | [Version]: 2.4.1'
    print '========================================================================='
    print ' [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework'
    print '========================================================================='
    print ""
    
    if settings.OPERATING_SYSTEM != "Kali":
        print helpers.color(' [!] WARNING: Official support for Kali Linux (x86) only at this time!', warning=True)
        print helpers.color(' [!] WARNING: Continue at your own risk!\n', warning=True)
    
    # check to make sure the current OS is supported,
    # print a warning message if it's not and exit
    if settings.OPERATING_SYSTEM == "Windows" or settings.OPERATING_SYSTEM == "Unsupported":
        print helpers.color(' [!] ERROR: Your operating system is not currently supported...\n', warning=True)
        print helpers.color(' [!] ERROR: Request your distribution at the GitHub repository...\n', warning=True)
        sys.exit()

def helpmsg(commands, showTitle=True):
    """
    Print a help menu.
    """
    
    if showTitle:
        title()
    
    print " Available commands:\n"
    
    # list commands in sorted order
    #for cmd in sorted(commands.iterkeys(), reverse=True):
    for (cmd, desc) in commands:
        
        print "\t%s\t%s" % ('{0: <12}'.format(cmd), desc)

    print ""

def helpModule(module):
    """
    Print the first text chunk for each established method in a module.

    module: module to write output from, format "folder.folder.module"
    """

    # split module.x.y into "from module.x import y" 
    t = module.split(".")
    importName = "from " + ".".join(t[:-1]) + " import " + t[-1]

    # dynamically do the import
    exec(importName)
    moduleName = t[-1]

    # extract all local functions from the imported module, 
    # referenced here by locals()[moduleName]
    functions = [locals()[moduleName].__dict__.get(a) for a in dir(locals()[moduleName]) if isinstance(locals()[moduleName].__dict__.get(a), types.FunctionType)]

    # pull all the doc strings out from said functions and print the top chunk
    for function in functions:
        base = function.func_doc
        base = base.replace("\t", " ")
        doc = "".join(base.split("\n\n")[0].strip().split("\n"))
        # print function.func_name + " : " + doc
        print helpers.formatLong(function.func_name, doc)

def endmsg():
    """
    Print the exit message.
    """
    print " [*] Your payload files have been generated, don't get caught!" 
    print helpers.color(" [!] And don't submit samples to any online scanner! ;)\n", warning=True)
