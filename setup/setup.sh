#!/bin/bash

# Setup Script for Kali to use PyInstaller

# Install MinGW for C payloads
apt-get install mingw-w64

# install mono for C# payloads
apt-get install monodoc-browser
apt-get install monodevelop
apt-get install mono-mcs

if [ -f /root/.wine/drive_c/Python27/python.exe ]
then
	rm -rf ../setup
	echo "Python already installed.. skipping install"
else

	# Download required files, doing no check cert because wget is having an issue with our wildcard cert
	# if you're reading this, and actually concerned you might be mitm, use a browser and just download these
	# files and then just comment these next two lines out :)
	wget https://www.veil-evasion.com/InstallMe/requiredfiles.zip --no-check-certificate
	wget https://www.veil-evasion.com/InstallMe/pyinstaller-2.0.zip --no-check-certificate

	# Unzip Setup Files
	unzip requiredfiles.zip

	# Prepare Wine Directories
	mkdir -p ~/.wine/drive_c/Python27/Lib/
	cp distutils -r ~/.wine/drive_c/Python27/Lib/
	cp tcl -r ~/.wine/drive_c/Python27/
	cp Tools -r ~/.wine/drive_c/Python27/

	# Install Setup Files
	wine msiexec /i python-2.7.5.msi
	wine pywin32-218.win32-py2.7.exe
	wine pycrypto-2.6.win32-py2.7.exe
	unzip -d ~/ pyinstaller-2.0.zip

	# Clean Up Setup Files
	rm python-2.7.5.msi
	rm pywin32-218.win32-py2.7.exe
	rm pycrypto-2.6.win32-py2.7.exe
	rm pyinstaller-2.0.zip
	rm requiredfiles.zip
	rm setup.sh

	# Remove Temp Directories
	rm -rf distutils
	rm -rf tcl
	rm -rf Tools
	rm -rf ../setup

fi
# run ./config/update.py
cd ../config
python update.py