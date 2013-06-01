# Import Modules
import string
import random

# Function to create random variable names.
def randomString():
    random_string = ''.join(random.choice(string.ascii_letters) for x in range(15))
    return random_string
