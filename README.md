#Veil

Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions.

Veil was originally developed by @ChrisTruncer.  Veil is currently under active support by @ChrisTruncer and @TheMightyShiv. 

Greetz: 
@jasonjfrank
@mjmaley
@davidpmcguire

##Software Requirements:

###Linux
1.  Use Kali (x86) and all dependencies are pre-installed

- or - 

1.  Install Python 2.7
2.  Install PyCrypto >= 2.3

### Windows
1.  Python (tested with x86 - http://www.python.org/download/releases/2.7/)
2.  Py2Exe (http://sourceforge.net/projects/py2exe/files/py2exe/0.6.9/)
3.  PyCrypto (http://www.voidspace.org.uk/python/modules.shtml)


##Setup (tldr;)

Run setup script on Kali x86 (for Pyinstaller).
Install Python 2.7, Py2Exe, and PyCrypto on a Windows computer (for Py2Exe).  

##Description
Veil was designed to run on Kali Linux, but should function on any system capable of executing python scripts.  Simply call Veil from the command line, and follow the menu to generate a payload.  Upon creating the payload, veil will ask if you would like the payload file to be converted into an executable by Pyinstaller or Py2Exe.

If using Pyinstaller, Veil will convert your payload into an executable within Kali.

If using Py2Exe, Veil will create three files:

* payload.py - The payload file
* setup.py - Required file for Py2Exe
* runme.bat - Batch script for compiling the payload into a Windows executable

Move all three files onto your Windows machine with Python installed.  All three files should be placed in the root of the directory Python was installed to (likely C:\Python27).  Run the batch script to convert the Python script into an executable format.  

Place the executable file on your target machine through any means necessary and don't get caught!
