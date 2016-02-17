"""

Contains any miscellaneous helper methods useful across multiple modules.

"""

import random, string, base64, zlib, re, textwrap, commands, settings, os, sys


def color(string, status=True, warning=False, bold=True, yellow=False):
    """
    Change text color for the linux terminal, defaults to green.

    Set "warning=True" for red.
    """
    attr = []
    if status:
        # green
        attr.append('32')
    if warning:
        # red
        attr.append('31')
    if bold:
        attr.append('1')
    if yellow:
        attr.append('33')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)


def inflate( b64string ):
    """
    Decode/decompress a base64 string. Used in powershell invokers.
    """
    decoded_data = base64.b64decode( b64string )
    return zlib.decompress( decoded_data , -15)


def deflate( string_val ):
    """
    Compress/base64 encode a string. Used in powershell invokers.
    """
    zlibbed_str = zlib.compress( string_val )
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode( compressed_string )


def LHOST():
    """
    Return the IP of eth0
    """
    return commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1]


def isValidHostname(hostname):
    """
    Try to validate the passed host name, return True or False.
    """
    if len(hostname) > 255: return False
    if hostname[-1:] == ".": hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def formatLong(title, message, frontTab=True, spacing=16):
    """
    Print a long title:message with our standardized formatting.
    Wraps multiple lines into a nice paragraph format.
    """

    lines = textwrap.wrap(textwrap.dedent(message).strip(), width=50)
    returnString = ""

    i = 1
    if len(lines) > 0:
        if frontTab:
            returnString += "\t%s%s" % (('{0: <%s}'%spacing).format(title), lines[0])
        else:
            returnString += " %s%s" % (('{0: <%s}'%(spacing-1)).format(title), lines[0])
    while i < len(lines):
        if frontTab:
            returnString += "\n\t"+' '*spacing+lines[i]
        else:
            returnString += "\n"+' '*spacing+lines[i]
        i += 1
    return returnString


#################################################################
#
# Randomization/obfuscation methods.
#
#################################################################

def randomString(length=-1):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    """
    if length == -1: length = random.randrange(6,16)
    random_string = ''.join(random.choice(string.ascii_letters) for x in range(length))
    return random_string


def randomKey(b=32):
    """
    Returns a random string/key of "b" characters in length, defaults to 32
    """
    return ''.join(random.choice(string.ascii_letters + string.digits + "{}!@#$^&()*&[]|,./?") for x in range(b))


def randomNumbers(b=6):
    """
    Returns a random string/key of "b" characters in length, defaults to 5
    """
    random_number = int(''.join(random.choice(string.digits) for x in range(b))) + 10000

    if random_number < 100000:
        random_number = random_number + 100000

    return random_number


def randomLetter():
    """
    Returns a random ascii letter.
    """
    return random.choice(string.ascii_letters)


def shuffle(l):
    """
    Shuffle the passed list.
    """
    random.shuffle(l)


def obfuscateNum(N, mod):
    """
    Take a number and modulus and return an obsucfated form.

    Returns a string of the obfuscated number N
    """
    d = random.randint(1, mod)
    left = int(N/d)
    right = d
    remainder = N % d
    return "(%s*%s+%s)" %(left, right, remainder)


#################################################################
#
# HTTP related helpers.
#
#################################################################

# helper for the metasploit http checksum algorithm
def checksum8(s):
    # hard rubyish way -> return sum([struct.unpack('<B', ch)[0] for ch in s]) % 0x100
    return sum([ord(ch) for ch in s]) % 0x100


# generate a metasploit http handler compatible checksum for the URL
def genHTTPChecksum(value="CONN"):
    checkValue = 0
    if value == "INITW": checkValue = 92 # normal initiation
    elif value == "INIT_CONN": checkValue = 95 # stageless session
    else: checkValue = 98 # existing session ("CONN")

    chk = string.ascii_letters + string.digits
    for x in xrange(64):
        uri = "".join(random.sample(chk,3))
        r = "".join(sorted(list(string.ascii_letters+string.digits), key=lambda *args: random.random()))
        for char in r:
            if checksum8(uri + char) == checkValue:
                return uri + char
