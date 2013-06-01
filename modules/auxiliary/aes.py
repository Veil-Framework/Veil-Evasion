# Import Modules
import string
import random

# Generate Random AES Key Function
def aesKey():
    random_aes = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(32))
    return random_aes
