"""
Contains methods for creating any supporting files for payloads.

"""

import os
import sys
from modules.common import shellcode
from modules.common import messages
from modules.common import helpers
from config import veil

def supportingFiles(language, payloadFile, options):
	"""
	Takes a specific language and payloadFile name written to and generates
	any necessary support files, and/or compiles the payload to an .exe.

	Currently only handles python and c

	options['method'] = "py2exe" or "pyinstaller" currently for python payloads
	"""
	if language == "python":

		# if we aren't passed any options, do the interactive menu
		if len(options) == 0:

			if veil.OPERATING_SYSTEM == "Windows":
				options['method'] = "py2exe"
			else:
				# if we have a linux distro, continue...
				# Determine if the user wants Pyinstaller or Py2Exe.
				print '\n [?] How would you like to create your payload executable?\n'
				print '		1 - Pyinstaller (default)'
				print '		2 - Py2Exe\n'

				PyMaker = raw_input(" [>] Please enter the number of your choice: ")
				if PyMaker == "1" or PyMaker == "":
					options['method'] = "pyinstaller"
				else:
					options['method'] = "py2exe"

		if options['method'] == "py2exe":

			nameBase = payloadFile.split("/")[-1].split(".")[0]

			# Generate setup.py File for Py2Exe
			SetupFile = open(veil.PAYLOAD_SOURCE_PATH + '/setup.py', 'w')
			SetupFile.write("from distutils.core import setup\n")
			SetupFile.write("import py2exe, sys, os\n\n")
			SetupFile.write("setup(\n")
			SetupFile.write("\toptions = {'py2exe': {'bundle_files': 1}},\n")
			SetupFile.write("\tzipfile = None,\n")
			SetupFile.write("\twindows=['"+nameBase+".py']\n")
			SetupFile.write(")")
			SetupFile.close()

			# Generate Batch script for Compiling on Windows Using Py2Exe
			RunmeFile = open(veil.PAYLOAD_SOURCE_PATH + '/runme.bat', 'w')
			RunmeFile.write('rem Batch Script for compiling python code into an executable\n')
			RunmeFile.write('rem on windows with py2exe\n')
			RunmeFile.write('rem Usage: Drop into your Python folder and click, or anywhere if Python is in your system path\n\n')
			RunmeFile.write("python setup.py py2exe\n")
			RunmeFile.write('cd dist\n')
			exeName = ".".join(payloadFile.split(".")[:-1]) + ".exe"
			RunmeFile.write('move '+nameBase+'.exe ../\n')
			RunmeFile.write('cd ..\n')
			RunmeFile.write('rmdir /S /Q build\n')
			RunmeFile.write('rmdir /S /Q dist\n')
			RunmeFile.close()

			print helpers.color("\npy2exe files 'setup.py' and 'runme.bat' written to:\n"+veil.PAYLOAD_SOURCE_PATH + "\n")

		# Else, Use Pyinstaller (used by default)
		else:
			# Check for Wine python.exe Binary (Thanks to darknight007 for this fix.)
			# Thanks to Tim Medin for patching for non-root non-kali users
			if(os.path.isfile(os.path.expanduser('~/.wine/drive_c/Python27/python.exe'))):

				# extract the payload base name and turn it into an .exe
				exeName = ".".join(payloadFile.split("/")[-1].split(".")[:-1]) + ".exe"

				outputPath = veil.PAYLOAD_COMPILED_PATH
				# TODO: os.system() is depreciated, use subprocess or commands instead
				os.system('wine ' + os.path.expanduser('~/.wine/drive_c/Python27/python.exe') + ' ' + os.path.expanduser('~/pyinstaller-2.0/pyinstaller.py') + ' --noconsole --onefile ' + payloadFile )
				os.system('mv dist/'+exeName+' ' + veil.PAYLOAD_COMPILED_PATH)
				os.system('rm -rf dist')
				os.system('rm -rf build')
				os.system('rm *.spec')
				os.system('rm logdict*.*')

				messages.title()
				print "\n [*] Executable written to: " +  helpers.color(veil.PAYLOAD_COMPILED_PATH + exeName)

			else:
				# Tim Medin's Patch for non-root non-kali users
				messages.title()
				print helpers.color("\n [!] ERROR: Can't find python.exe in " + os.path.expanduser('~/.wine/drive_c/Python27/'), warning=True)
				print helpers.color(" [!] ERROR: Make sure the python.exe binary exists before using PyInstaller.", warning=True)
				sys.exit()

	elif language == "c":

		# extract the payload base name and turn it into an .exe
		exeName = ".".join(payloadFile.split("/")[-1].split(".")[:-1]) + ".exe"
		outputPath = os.getcwd() + "/output/compiled/"

		# Compile our C code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
		os.system('i686-w64-mingw32-gcc -Wl,-subsystem,windows '+payloadFile+' -o ' + veil.PAYLOAD_COMPILED_PATH + exeName)

		print "\n [*] Executable written to: " +  helpers.color(veil.PAYLOAD_COMPILED_PATH + exeName)

	elif language == "c#":

		# extract the payload base name and turn it into an .exe
		exeName = ".".join(payloadFile.split("/")[-1].split(".")[:-1]) + ".exe"
		outputPath = os.getcwd() + "/output/compiled/"

		# Compile our C code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
		os.system('mcs -platform:x86 -target:winexe '+payloadFile+' -out:' + veil.PAYLOAD_COMPILED_PATH + exeName)

		print "\n [*] Executable written to: " +  helpers.color(veil.PAYLOAD_COMPILED_PATH + exeName)


	else:
		messages.title()
		print helpers.color("\n [!] ERROR: Only python, c, and c# compiling is currently supported.\n", warning=True)


