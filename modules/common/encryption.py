"""
Contains any encryption-related methods that may be reused.

"""

# Import Modules
import string
import random
import base64
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4

from modules.common import helpers

# AES Block Size and Padding
BlockSize = 32
Padding = '{'



#################################################################
#
# Misc helper functions.
#
#################################################################

"""
Lambda function for Padding Encrypted Text to Fit the Block
"""
pad = lambda s: s + (BlockSize - len(s) % BlockSize) * Padding


"""
Pad a string to block size, AES encrypt, then base64encode.
"""
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))


"""
Base64Decode a string, AES descrypt it, then strip padding.
"""
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(Padding)



#################################################################
#
# Various encryption methods.
#
#################################################################


def b64sub(s, key):
    """
    "Encryption" method that base64 encodes a given string, 
    then does a randomized alphabetic letter substitution.
    """
    enc_tbl = string.maketrans(string.ascii_letters, key)
    return string.translate(base64.b64encode(s), enc_tbl)


def encryptAES(s):
    """
    Generates a random AES key, builds an AES cipher,
    encrypts passed 's' and returns (encrypted, randomKey)
    """
    # Generate Random AES Key
    key = helpers.randomKey()

    # Create Cipher Object with Generated Secret Key
    cipher = AES.new(key)

    # actually encrypt the text
    encrypted = EncodeAES(cipher, s)

    # return a tuple of (encodedText, randomKey)
    return (encrypted, key)


def encryptDES(s):
    """
    Generates a random DES key and IV, builds an DES cipher,
    encrypts passed 's' and returns (encrypted, (randomKey, randomIV))
    """
    # get random IV Value and ARC Key
    iv = helpers.randomKey(8)
    key = helpers.randomKey(8)

    # Create DES Object and encrypt our payload
    desmain = DES.new(key, DES.MODE_CFB, iv)
    encrypted = desmain.encrypt(s)

    return (encrypted, (key,iv) )


def encryptARC(s):
    """
    Generates a random ARC key and IV, builds an ARC cipher,
    encrypts passed 's' and returns (encrypted, (randomKey, randomIV))
    """
    # get random IV Value and ARC Key
    iv = helpers.randomKey(8)
    key = helpers.randomKey(8)

    # Create ARC Object and encrypt our payload
    arc4main = ARC4.new(key)
    encrypted = arc4main.encrypt(s)

    return (encrypted, (key,iv) )



#################################################################
#
# 'Crypters'/source code obfuscators.
#
#################################################################

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
    key = helpers.randomKey(32)
    cipherEnc = AES.new(key)

    # encrypt the input file (less the imports)
    encrypted = EncodeAES(cipherEnc, "\n".join(codebase))
    
    # some random variable names
    b64var = helpers.randomString(5)
    aesvar = helpers.randomString(5)

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
