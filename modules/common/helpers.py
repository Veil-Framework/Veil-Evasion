"""
Contains any miscellaneous helper methods useful across multiple modules.

"""

import random, string, base64, zlib, re, textwrap

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

def color(string, status=True, warning=False, bold=True):
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

def isValidHostname(hostname):
    if len(hostname) > 255: return False
    if hostname[-1:] == ".": hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def formatLong(title,message, frontTab=True, spacing=16):
    """
    Print a long title:message with our standardized formatting.
    Wraps multiple lines into a nice paragraph format
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
