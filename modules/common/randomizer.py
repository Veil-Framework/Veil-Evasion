"""
Contains any randomization methods useful across multiple modules.

"""

import string
import random

def randomString(length=15):
	"""
	Returns a random string of "length" characters, default 15.
	"""
	random_string = ''.join(random.choice(string.ascii_letters) for x in range(length))
	return random_string

def randomKey(b=32):
	"""
	Returns a random string/key of "b" characters in length, defaults to 32
	"""
	return ''.join(random.choice(string.ascii_letters + string.digits + "{}!@#$^&()*&[]|,./?") for x in range(b))

def randomLetter():
	"""
	Returns a random ascii letter.
	"""
	return random.choice(string.ascii_letters)
