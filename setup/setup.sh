#!/bin/bash

# Setup Script for Kali to use PyInstaller

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
