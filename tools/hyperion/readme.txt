###############################################################################
#                                                                             #
#         ~    .__ °.__   0       o                    ^   .__ °__  `´        #
#  °____) __ __|  | | °|   ______°____ 0 ____  __ _________|__|/  |_ ___.__.  #
#  /    \|  | °\  |°|  | °/  ___// __ \_/ ___\|  | °\_  __ \ o\   __<   |  |  #
# | o°|  \  |  /  |_|  |__\___ \\  ___/\ °\___| o|  /|  | \/  ||  |° \___ O|  #
# |___|  /____/|____/____/____ °>\___  >\___  >____/ |__|° |__||__|  / ____|  #
# `´´`´\/´`nullsecurity team`´\/`´´`´\/`´``´\/  ``´```´```´´´´`´``0_o\/´´`´´  #
#                                                                             #
# Hyperion: A runtime PE-Crypter                                              #
#                                                                             #
# VERSION                                                                     #
# 1.0                                                                         #
#                                                                             #
# DATE                                                                        #
# 25/05/2012                                                                  #
#                                                                             #
# AUTHOR                                                                      #
# belial - http://www.nullsecurity.net/                                       #
#                                                                             #
# LICENSE                                                                     #
# BSD-License                                                                 #
#                                                                             #
# DESCRIPTION                                                                 #
# Hyperion is a runtime encrypter for 32-bit portable executables. It is a    #
# reference implementation and bases on the paper "Hyperion: Implementation   #
# of a PE-Crypter". The paper describes the implementation details which      #
# aren't in the scope of this readme file.                                    #
# The crypter is a C/C++ project and can be compiled with the corresponding   #
# makefile (tested with Mingw and Visual Studio). Afterwards it is started    #
# via the command line and encrypts an input executable with AES-128. The     #
# encrypted file decrypts itself on startup (bruteforcing the AES key which   #
# may take a few seconds) and generates a log file for debug purpose. The key #
# space size can be changed in the crypter source code to speed up the brute  #
# force key search algorithm.                                                 #
#                                                                             #
# TODO                                                                        #
# - Late Binding of DLLs/APIs                                                 #
# - AV evasion                                                                #
# - Polymorphic generation of the container                                   #
# - Add .NET Support                                                          #
# - Change key space size via the command line                                #
#                                                                             #
# CHANGELOG:                                                                  #
#                                                                             #
# v1.0:                                                                       #
# - initial release                                                           #
#                                                                             #
###############################################################################