#!/bin/bash

# Print title
func_title(){
clear
echo '========================================================================='
echo ' Veil-Evasion Setup Script | [Updated]: 01.15.2015'
echo '========================================================================='
echo ' [Web]: https://www.veil-framework.com | [Twitter]: @VeilFramework'
echo '========================================================================='
}

# Validation checks function
func_validate(){
# Check User Permissions
if [ `whoami` != 'root' ]; then
     echo
     echo ' [ERROR]: Either Run This Setup Script As Root Or Use Sudo.'
     echo
     exit 1
fi

# Install the symmetricjsonrpc pip if it isn't already there
if [ -d /usr/local/lib/python2.7/dist-packages/symmetricjsonrpc/ ]; then
     echo
     echo ' [*] pip symmetricjsonrpc already installed, skipping.'
     echo
else
     echo
     echo ' [*] Installing symmetricjsonrpc pip.'
     echo
     apt-get install python-pip
     pip install symmetricjsonrpc
     echo
fi

# Check if Wine Python us already installed
if [ -f ~/.wine/drive_c/windows/system32/python27.dll ] && [ -f ~/.wine/drive_c/Python27/python.exe ]; then
     echo
     echo ' [*] Wine Python already installed.'
     echo
     echo ' [*] Initializing apt package installation.'
     func_apt_deps
     func_update_config
else
     echo
     echo ' [*] Initializing apt dependencies installation.'
     func_apt_deps
     echo
     echo ' [*] Initializing Wine Python dependencies installation.'
     func_python_deps
fi
}

# Install architecture dependent dependencies
func_apt_deps(){
# Check for 64-bit kernel
if [ `uname -m` == 'x86_64' ]; then
     echo
     echo ' [*] Adding i386 architecture to x86_64 system.'
     dpkg --add-architecture i386
     echo
     echo ' [*] Updating apt package lists.'
     apt-get update
     echo
     echo ' [*] Installing Wine i386 binaries.'
     apt-get install wine-bin:i386
fi

# Start apt dependency install
echo
echo ' [*] Installing apt dependencies.'
apt-get install mingw-w64 monodoc-browser monodevelop mono-mcs wine python python-crypto
}

# Install Wine Python dependent dependencies
func_python_deps(){
# Install Wine Python and dependencies
# Download required files, doing no check cert because wget is having an issue with our wildcard cert.
# If you're reading this and actually concerned, you might be MiTM, use a browser and just download these
# files and then just comment these next two lines out.
echo
echo ' [*] Downloading setup files from http://www.veil-framework.com.'
wget https://www.veil-framework.com/InstallMe/requiredfiles.zip --no-check-certificate
wget https://www.veil-framework.com/InstallMe/pyinstaller-2.0.zip --no-check-certificate

# Unzip setup files
echo
echo ' [*] Uncompressing setup archive.'
unzip requiredfiles.zip

# Prepare Wine directories
echo
echo ' [*] Preparing Wine directories.'
mkdir -p ~/.wine/drive_c/Python27/Lib/
cp distutils -r ~/.wine/drive_c/Python27/Lib/
cp tcl -r ~/.wine/drive_c/Python27/
cp Tools -r ~/.wine/drive_c/Python27/

# Install setup files
echo
echo ' [*] Installing Wine Python dependencies.'
wine msiexec /i python-2.7.5.msi
wine pywin32-218.win32-py2.7.exe
wine pycrypto-2.6.win32-py2.7.exe

if [ -d "/usr/share/pyinstaller" ]; then
     echo
     echo ' [*] PyInstaller already installed.'
else
     unzip -d /opt pyinstaller-2.0.zip
fi

# Clean up setup files
echo
echo ' [*] Cleaning up setup files.'
rm python-2.7.5.msi
rm pywin32-218.win32-py2.7.exe
rm pycrypto-2.6.win32-py2.7.exe
rm pyinstaller-2.0.zip
rm requiredfiles.zip

# Remove temp directories
echo
echo ' [*] Removing temporary directories.'
rm -rf distutils
rm -rf tcl
rm -rf Tools

# Update Veil config
func_update_config
}

func_update_config(){
# run ./config/update.py
echo
echo ' [*] Updating Veil-Framework config.'
cd ../config
python update.py
}

# Menu 
case $1 in
     # Force clean install of Wine Python dependencies
     --clean)
     if [ `whoami` != 'root' ]; then
          echo
          echo ' [ERROR]: Either run this setup script as root or use sudo.'
          echo
          exit 1
     fi

     # Bypass validation checks to force install dependencies
     func_title
     func_apt_deps
     func_python_deps
     ;;

     # Print help menu
     -h|--help)
     func_title
     echo
     echo '  [Usage]....: ${0} [OPTIONAL]'
     echo '  [Optional].:'
     echo '       --clean   = Force clean install of Python dependencies.'
     echo '       -h|--help = Show Help menu.'
     echo
     ;;

     # Run standard setup
     *)
     func_title
     func_validate
     ;;
esac
