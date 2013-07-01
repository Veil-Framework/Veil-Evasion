"""
Common terminal messages used across the framework.
"""

import os, sys
from config import veil
from modules.common import helpers

def title():
	"""
	Print the framework title, with version.
	"""
	os.system(veil.TERMINAL_CLEAR)
	print '========================================================================='
	print ' Veil | [Version]: 2.0'
	print '========================================================================='
	print ' [Web]: https://www.veil-evasion.com/ | [Twitter]: @veilevasion'
	print '========================================================================='
	print ""
	
	if veil.OPERATING_SYSTEM != "Kali":
		print helpers.color(' [!] WARNING: Official support for Kali Linux (x86) only at this time!', warning=True)
		print helpers.color(' [!] WARNING: Continue at your own risk!\n', warning=True)
	
	# check to make sure the current OS is supported,
	# print a warning message if it's not and exit
	if veil.OPERATING_SYSTEM == "Windows" or veil.OPERATING_SYSTEM == "Unsupported":
		print helpers.color(' [!] ERROR: Your operating system is not currently supported...\n', warning=True)
		print helpers.color(' [!] ERROR: Request your distribution at the GitHub repository...\n', warning=True)
		sys.exit()


def helpmsg(commands, showTitle=True):
	"""
	Print a help menu.
	"""
	
	if showTitle:
		title()
	
	print " Available commands:\n"
	
	# list commands in sorted order
	for cmd in sorted(commands.iterkeys(), reverse=True):
		
		print "\t%s\t%s" % ('{0: <12}'.format(cmd), commands[cmd])

	print ""

def endmsg():
	"""
	Print the exit message.
	"""
	print " [*] Your payload files have been generated, don't get caught!" 
	print helpers.color(" [!] And don't submit samples to any online scanner! ;)\n", warning=True)
