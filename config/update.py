#!/usr/bin/python

import platform, os, sys

"""

Take an options dictionary and update /etc/settings.py

"""
def generateConfig(options):
    
    config = """#!/usr/bin/python

##################################################################################################
#
# Veil configuration file                                               
#
# Run update.py to automatically set all these options.
#
##################################################################################################

"""

    config += '# OS to use (Kali/Backtrack/Debian/Windows)\n'
    config += 'OPERATING_SYSTEM="' + options['OPERATING_SYSTEM'] + '"\n\n'
    print " [*] OPERATING_SYSTEM = " + options['OPERATING_SYSTEM']

    config += '# Terminal clearing method to use\n'
    config += 'TERMINAL_CLEAR="' + options['TERMINAL_CLEAR'] + '"\n\n'
    print " [*] TERMINAL_CLEAR = " + options['TERMINAL_CLEAR']
    
    config += '# Veil base install path\n'
    config += 'VEIL_PATH="' + options['VEIL_PATH'] + '"\n\n'
    print " [*] VEIL_PATH = " + options['VEIL_PATH']
    
    source_path = os.path.expanduser(options["PAYLOAD_SOURCE_PATH"])
    config += '# Path to output the source of payloads\n'
    config += 'PAYLOAD_SOURCE_PATH="' + source_path + '"\n\n'
    print " [*] PAYLOAD_SOURCE_PATH = " + source_path

    # create the output source path if it doesn't exist
    if not os.path.exists(source_path): 
        os.makedirs(source_path)
        print " [*] Path '" + source_path + "' Created"
    
    compiled_path = os.path.expanduser(options["PAYLOAD_COMPILED_PATH"])
    config += '# Path to output compiled payloads\n'
    config += 'PAYLOAD_COMPILED_PATH="' + compiled_path +'"\n\n'
    print " [*] PAYLOAD_COMPILED_PATH = " + compiled_path

    # create the output compiled path if it doesn't exist
    if not os.path.exists( compiled_path ): 
        os.makedirs( compiled_path )
        print " [*] Path '" + compiled_path + "' Created"

    config += '# Path to temporary directory\n'
    config += 'TEMP_DIR="' + options["TEMP_DIR"] + '"\n\n'
    print " [*] TEMP_DIR = " + options["TEMP_DIR"]
    
    config += '# The path to the metasploit framework, for example: /usr/share/metasploit-framework/\n'
    config += 'METASPLOIT_PATH="' + options['METASPLOIT_PATH'] + '"\n\n'
    print " [*] METASPLOIT_PATH = " + options['METASPLOIT_PATH']

    config += '# The path to pyinstaller, for example: /usr/share/pyinstaller/\n'
    config += 'PYINSTALLER_PATH="' + options['PYINSTALLER_PATH'] + '"\n\n'
    print " [*] PYINSTALLER_PATH = " + options['PYINSTALLER_PATH']

    config += '# Default options to pass to msfvenom for shellcode creation\n'
    config += 'MSFVENOM_OPTIONS="' + options['MSFVENOM_OPTIONS'] + '"\n\n'
    print " [*] MSFVENOM_OPTIONS = " + options['MSFVENOM_OPTIONS']

    handler_path = os.path.expanduser(options["HANDLER_PATH"])
    # create the output compiled path if it doesn't exist
    if not os.path.exists( handler_path ): 
        os.makedirs( handler_path )
        print " [*] Path '" + handler_path + "' Created"

    config += '# Whether to generate a msf handler script and where to place it\n'
    config += 'GENERATE_HANDLER_SCRIPT="' + options['GENERATE_HANDLER_SCRIPT'] + '"\n'
    print " [*] GENERATE_HANDLER_SCRIPT = " + options['GENERATE_HANDLER_SCRIPT']
    config += 'HANDLER_PATH="' + handler_path + '"\n\n'
    print " [*] HANDLER_PATH = " + handler_path

    hash_path = os.path.expanduser(options["HASH_LIST"])
    config += 'HASH_LIST="' + hash_path + '"\n\n'
    print " [*] HASH_LIST = " + hash_path

    if platform.system() == "Linux":
        issue = open("/etc/issue").read()
        if issue.startswith("Kali"):
            # create the output compiled path if it doesn't exist
            if not os.path.exists("/etc/veil/"): 
                os.makedirs("/etc/veil/")
                print " [*] Path '/etc/veil/' Created"
            f = open("/etc/veil/settings.py", 'w')
            f.write(config)
            f.close()
            print " [*] Configuration File Written To '/etc/veil/settings.py'\n"
        else:
            f = open("settings.py", 'w')
            f.write(config)
            f.close()
            print " [*] Configuration File Written To " + options['VEIL_PATH'] + "config/settings.py\n"
    elif platform.system() == "Windows":
        f = open("settings.py", 'w')
        f.write(config)
        f.close()
        print " [*] Configuration File Written To " + options['VEIL_PATH'] + "config/settings.py\n"
    else:
        print " [!] ERROR: PLATFORM NOT SUPPORTED"
        sys.exit()

if __name__ == '__main__':

    options = {}

    if platform.system() == "Linux":
        
        # check /etc/issue for the exact linux distro
        issue = open("/etc/issue").read()
        
        if issue.startswith("Kali"):
            options["OPERATING_SYSTEM"] = "Kali"
            options["TERMINAL_CLEAR"] = "clear"
            options["METASPLOIT_PATH"] = "/usr/share/metasploit-framework/"
            if os.path.isdir('/usr/share/pyinstaller'):
                options["PYINSTALLER_PATH"] = "/usr/share/pyinstaller/"
            else:
                options["PYINSTALLER_PATH"] = "/opt/pyinstaller-2.0/"
        elif issue.startswith("BackTrack"):
            options["OPERATING_SYSTEM"] = "BackTrack"
            options["TERMINAL_CLEAR"] = "clear"
            options["METASPLOIT_PATH"] = "/opt/metasploit/msf3/"
            options["PYINSTALLER_PATH"] = "/opt/pyinstaller-2.0/"
        else:
            options["OPERATING_SYSTEM"] = "Linux"
            options["TERMINAL_CLEAR"] = "clear"
            msfpath = raw_input(" [>] Please enter the path of your metasploit installation: ")
            options["METASPLOIT_PATH"] = msfpath
            options["PYINSTALLER_PATH"] = "/opt/pyinstaller-2.0/"
        
        veil_path = "/".join(os.getcwd().split("/")[:-1]) + "/"
        options["VEIL_PATH"] = veil_path
        options["PAYLOAD_SOURCE_PATH"] = "~/veil-output/source/"
        options["PAYLOAD_COMPILED_PATH"] = "~/veil-output/compiled/"
        options["TEMP_DIR"]="/tmp/"
        options["MSFVENOM_OPTIONS"]=""
        options["GENERATE_HANDLER_SCRIPT"] = "True"
        options["HANDLER_PATH"] = "~/veil-output/handlers/"
        options["HASH_LIST"] = "~/veil-output/hashes.txt"


    # not current supported
    elif platform.system() == "Windows":
        options["OPERATING_SYSTEM"] = "Windows"
        options["TERMINAL_CLEAR"] = "cls"

        veil_path = "\\".join(os.getcwd().split("\\")[:-1]) + "\\"
        options["VEIL_PATH"] = veil_path
        
        options["PAYLOAD_SOURCE_PATH"] = veil_path + "output\\source\\"
        options["PAYLOAD_COMPILED_PATH"] = veil_path + "output\\compiled\\"
        options["TEMP_DIR"]="C:\\Windows\\Temp\\"
        
        msfpath = raw_input(" [>] Please enter the path of your metasploit installation: ")
        options["METASPLOIT_PATH"] = msfpath

        pyinspath = raw_input(" [>] Please enter the path of your pyinstaller installation: ")
        options["PYINSTALLER_PATH"] = pyinspath

        options["MSFVENOM_OPTIONS"]=""
    
    # unsupported platform... 
    else:
        print " [!] ERROR: PLATFORM NOT SUPPORTED"
        sys.exit()

    generateConfig(options)
