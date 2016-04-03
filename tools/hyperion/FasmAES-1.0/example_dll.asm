format PE CONSOLE 4.0
entry start

include 'win32a.inc'

TEXTSIZE equ 0x30

section '.text' code readable executable

  start:

    ;invoke aesEncrypt, TEXTSIZE, clear_msg, enc_msg, key128
    ;invoke aesDecrypt, TEXTSIZE, enc_msg, dec_msg, key128
    invoke aesEncrypt, TEXTSIZE, clear_msg, clear_msg, key128
    invoke aesDecrypt, TEXTSIZE, clear_msg, clear_msg, key128
    invoke ExitProcess, 0

section '.data' data readable writeable


  clear_msg db 'hello world, this is a secret text',\
	       0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  enc_msg   rb TEXTSIZE
  dec_msg   rb TEXTSIZE

  key128    db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,\
	       0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

section '.idata' import data readable writeable

  library kernel,'KERNEL32.DLL',\
	  aes,'AES10.DLL'

  import kernel,\
	 ExitProcess,'ExitProcess'

  import aes,\
	 aesEncrypt,'aesEncrypt',\
	 aesDecrypt,'aesDecrypt'