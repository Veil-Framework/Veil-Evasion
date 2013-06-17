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


# AES Block Size and Padding
BlockSize = 32
Padding = '{'


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


"""
"Encryption" method that base64 encodes a given string, 
then does a randomized alphabetic letter substitution.
"""
def b64sub(s, key):
	enc_tbl = string.maketrans(string.ascii_letters, key)
	return string.translate(base64.b64encode(s), enc_tbl)
 
