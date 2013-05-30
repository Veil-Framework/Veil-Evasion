#!/bin/bash

# Script for setting up Kali to use pyinstaller

# Unzip the setup files
unzip requiredfiles.zip

# Move directories to the right spot
mkdir -p ~/.wine/drive_c/Python27/Lib/
cp distutils -r ~/.wine/drive_c/Python27/Lib/
cp tcl -r ~/.wine/drive_c/Python27/
cp Tools -r ~/.wine/drive_c/Python27/

# Install the files
wine msiexec /i python-2.7.5.msi
wine pywin32-218.win32-py2.7.exe
wine pycrypto-2.6.win32-py2.7.exe
unzip -d ~/ pyinstaller-2.0.zip

rm python-2.7.5.msi
rm pywin32-218.win32-py2.7.exe
rm pycrypto-2.6.win32-py2.7.exe
rm pyinstaller-2.0.zip
rm requiredfiles.zip

rm -rf distutils
rm -rf tcl
rm -rf Tools


