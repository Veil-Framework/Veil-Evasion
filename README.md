# Veil-Evasion

Veil-Evasion is a tool designed to generate metasploit payloads that bypass common anti-virus solutions.

NOTE: `./setup/setup.sh` should be re-run on every major version update. If you receive any major errors on running Veil-Evasion, first try re-running this script to install any additional packages and update the common configuration file.

Veil-Evasion is currently under active support by @ChrisTruncer, @TheMightyShiv, @HarmJ0y.

Thanks to:
* @jasonjfrank
* @mjmaley
* @davidpmcguire

## Software Requirements:

### Linux

1.  Use Kali (x86) and all dependencies are pre-installed

**or**

1.  Install Python 2.7
2.  Install PyCrypto >= 2.3

### Windows (for Py2Exe compilation)

1.  Python (tested with x86 - http://www.python.org/download/releases/2.7/)
2.  Py2Exe (http://sourceforge.net/projects/py2exe/files/py2exe/0.6.9/)
3.  PyCrypto (http://www.voidspace.org.uk/python/modules.shtml)
4.  PyWin32 (http://sourceforge.net/projects/pywin32/files/pywin32/Build%20218/pywin32-218.win32-py2.7.exe/download)

## Setup (tl;dr)

Run `./setup/setup.sh` on Kali x86 (for Pyinstaller).

Install Python 2.7, Py2Exe, PyCrypto, and PyWin32 on a Windows computer (for Py2Exe).

### Quick Install

```bash
sudo apt-get -y install git
git clone https://github.com/Veil-Framework/Veil-Evasion.git
cd Veil-Evasion/
bash setup/setup.sh -s
```

## Description

Veil-Evasion was designed to run on Kali Linux, but should function on any system capable of executing python scripts.  Simply call Veil-Evasion from the command line, and follow the menu to generate a payload.  Upon creating the payload, Veil-Evasion will ask if you would like the payload file to be converted into an executable by Pyinstaller or Py2Exe.

If using Pyinstaller, Veil-Evasion will convert your payload into an executable within Kali.

If using Py2Exe, Veil-Evasion will create three files:

* payload.py - The payload file
* setup.py - Required file for Py2Exe
* runme.bat - Batch script for compiling the payload into a Windows executable

Move all three files onto your Windows machine with Python installed.  All three files should be placed in the root of the directory Python was installed to (likely C:\Python27).  Run the batch script to convert the Python script into an executable format.

Place the executable file on your target machine through any means necessary and don't get caught!
