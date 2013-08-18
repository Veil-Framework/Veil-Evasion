#!/bin/bash

# Install Dependencies
if [ `whoami` == 'root' ]
then
	if [ `uname -m` == 'x86_64' ]
	then
		dpkg --add-architecture i386
		apt-get update
		apt-get install wine-bin:i386
	fi
    apt-get install mingw-w64 monodoc-browser monodevelop mono-mcs wine python python-crypto
elif [ `which sudo|wc -l` == '1' ]
then
	if [ `uname -m` == 'x86_64' ]
	then
		sudo dpkg --add-architecture i386
		sudo apt-get update
		sudo apt-get install wine-bin:i386
	fi
    sudo apt-get install mingw-w64 monodoc-browser monodevelop mono-mcs wine python python-crypto
else
    echo '[ERROR]: Either run this setup script as root or install sudo.'
fi

# Install Wine Python and Dependencies
if [ -f ~/.wine/drive_c/Python27/python.exe ]
then
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

	# Remove Temp Directories
	rm -rf distutils
	rm -rf tcl
	rm -rf Tools
fi

# run ./config/update.py
cd `dirname $0`/../config
python update.py
