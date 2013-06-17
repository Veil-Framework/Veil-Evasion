"""
Contains any encrypters that can be run on source code 
AFTER their initial generation.

"""

# Import Modules
import random
import string
import base64

from modules.common import randomizer
from modules.common import encryption
from Crypto.Cipher import AES


def pyherion(code):
	"""
	Generates a crypted hyperion'esque version of python code using
	base64 and AES with a random key, wrapped in an exec() dynamic launcher.

	code = the python source code to encrypt

	Returns the encrypted python code as a string.
	"""

	imports = list()
	codebase = list()
	
	# strip out all imports from the code so pyinstaller can properly
	# launch the code by preimporting everything at compiletime
	for line in code.split("\n"):
		if not line.startswith("#"): # ignore commented imports...
			if "import" in line:
				imports.append(line)
			else:
				codebase.append(line)
	
	# generate a random 256 AES key and build our AES cipher
	key = randomizer.randomKey(32)
	cipherEnc = AES.new(key)

	# encrypt the input file (less the imports)
	encrypted = encryption.EncodeAES(cipherEnc, "\n".join(codebase))
	
	# some random variable names
	b64var = randomizer.randomString(5)
	aesvar = randomizer.randomString(5)

	# randomize our base64 and AES importing variable
	imports.append("from base64 import b64decode as %s" %(b64var))
	imports.append("from Crypto.Cipher import AES as %s" %(aesvar))

	# shuffle up our imports
	random.shuffle(imports)
	
	# add in the AES imports and any imports found in the file
	crypted = ";".join(imports) + "\n"

	# the exec() launcher for our base64'ed encrypted string
	crypted += "exec(%s(\"%s\"))" % (b64var,base64.b64encode("exec(%s.new(\"%s\").decrypt(%s(\"%s\")).rstrip('{'))\n" %(aesvar,key,b64var,encrypted)))

	return crypted
