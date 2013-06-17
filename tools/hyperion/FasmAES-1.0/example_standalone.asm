format PE CONSOLE 4.0
entry start

include 'win32a.inc'
include 'aes/aes.inc'

TEXTSIZE equ 3*BLOCK_SIZE

section '.text' code readable executable

  start:
    stdcall encAES, TEXTSIZE, clear_msg, enc_msg, key128
    stdcall decAES, TEXTSIZE, enc_msg, dec_msg, key128

    ;stdcall encAES, TEXTSIZE, clear_msg, enc_msg, key192
    ;stdcall decAES, TEXTSIZE, enc_msg, dec_msg, key192

    ;stdcall encAES, TEXTSIZE, clear_msg, enc_msg, key256
    ;stdcall decAES, TEXTSIZE, enc_msg, dec_msg, key256

    invoke getchar
    invoke ExitProcess, 0

include 'aes/aes.asm'

section '.data' data readable writeable

  clear_msg db 'hello world, this is a secret text',\
	       0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  enc_msg   rb TEXTSIZE
  dec_msg   rb TEXTSIZE

  key128    db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,\
	       0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
  key192    db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,\
	       0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c,\
	       0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
  key256    db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,\
	       0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c,\
	       0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,\
	       0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

section '.idata' import data readable writeable

  library kernel,'KERNEL32.DLL',\
	  msvcrt,'MSVCRT'

  import kernel,\
	 ExitProcess,'ExitProcess'

  import msvcrt,\
	 printf,'printf',\
	 getchar,'_fgetchar'