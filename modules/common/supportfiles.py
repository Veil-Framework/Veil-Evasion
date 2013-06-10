# Pyinstaller method is also used in SET by Dave Kennedy when working with python payloads
# Import Modules
import os
import sys
from modules.auxiliary import shellcode
from modules.common import messages

# Generating Supporting Files Function
def supportingFiles():

    # Print Title
    messages.title()

    # Determine if the user wants Pyinstaller or Py2Exe.
    print '\n[?] How would you like to create your payload executable?\n'
    print ' 1 - Pyinstaller (default)'
    print ' 2 - Py2Exe\n'
    try:
        PyMaker = raw_input("[>] Please enter the number of your choice: ")
    except KeyboardInterrupt:
        print "\n[!] Exiting...\n"
        sys.exit()

    # Python-Wrapper If-statement
    if PyMaker == "2":
        # Generate setup.py File for Py2Exe
        SetupFile = open('setup.py', 'w')
        SetupFile.write("from distutils.core import setup\n")
        SetupFile.write("import py2exe, sys, os\n\n")
        SetupFile.write("setup(\n")
        SetupFile.write("\toptions = {'py2exe': {'bundle_files': 1}},\n")
        SetupFile.write("\tzipfile = None,\n")
        SetupFile.write("\twindows=['payload.py']\n")
        SetupFile.write(")")
        SetupFile.close()

        # Generate Batch script for Compiling on Windows Using Py2Exe
        RunmeFile = open('runme.bat', 'w')
        RunmeFile.write('rem Batch Script for compiling python code into an executable\n')
        RunmeFile.write('rem on windows with py2exe\n')
        RunmeFile.write('rem Developed by @ChrisTruncer\n\n')
        RunmeFile.write('rem Usage: Drop into your Python folder and click, or anywhere if Python is in your system path\n\n')
        RunmeFile.write("python setup.py py2exe\n")
        RunmeFile.write('cd dist\n')
        RunmeFile.write('move payload.exe ../\n')
        RunmeFile.write('cd ..\n')
        RunmeFile.write('rmdir /S /Q build\n')
        RunmeFile.write('rmdir /S /Q dist\n')
        RunmeFile.close()
        print shellcode.helpfulinfo    

     # Else, Use Pyinstaller (used by default)
    else:
        # Check for Wine python.exe Binary (Thanks to darknight007 for this fix.)
        if(os.path.isfile('/root/.wine/drive_c/Python27/python.exe')):
            print
            os.system('wine /root/.wine/drive_c/Python27/python.exe /root/pyinstaller-2.0/pyinstaller.py --noconsole --onefile payload.py')
            os.system('mv dist/payload.exe .')
            os.system('rm -rf dist')
            os.system('rm -rf build')
            os.system('rm payload.spec')
            os.system('rm logdict*.*')
            os.system('rm payload.py')
            messages.title()
            print shellcode.helpfulinfo
        else:
            messages.title()
            print "\n[Error]: Can't find python.exe in /root/.wine/drive_c/Python27/."
            print "         Make sure the python.exe binary exists before using PyInstaller.\n"
            exit(1)
