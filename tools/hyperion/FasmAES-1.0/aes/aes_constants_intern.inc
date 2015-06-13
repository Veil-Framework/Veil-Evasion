;static for AES
BLOCK_SIZE		equ 16
COLUMN_SIZE		equ 4

if defined AES128
   KEY_SIZE		   = 16
   EXTENDED_KEY_SIZE	   = 176
   ROW_SIZE		   = 4
   ENCRYPTION_ROUNDS	   = 10
end if

if defined AES192
   KEY_SIZE		   = 24
   EXTENDED_KEY_SIZE	   = 208
   ROW_SIZE		   = 6
   ENCRYPTION_ROUNDS	   = 12
end if

if defined AES256
   KEY_SIZE		   = 32
   EXTENDED_KEY_SIZE	   = 240
   ROW_SIZE		   = 8
   ENCRYPTION_ROUNDS	   = 14
end if

;size of the sbox
SBOX_SIZE		equ 256

;size of the rcon table
RCON_SIZE		equ 256

;size of the Galois multiplication
;lookup tables
GALOIS_SIZE		equ 256