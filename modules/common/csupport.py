# Import Modules
import os
from modules.auxiliary import shellcode
from modules.common import messages

def compilemingw ():
    # Print Title
    messages.title()

    # Compile our C code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
    os.system('i686-w64-mingw32-gcc -Wl,-subsystem,windows payload.c -o payload.exe')
    os.system('rm payload.c')

    messages.title()
    messages.endmsg()
