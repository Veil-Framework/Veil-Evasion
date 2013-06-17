include 'sbox.asm'
include 'rcon.asm'
include 'keychain.asm'
include 'encryptionrounds.asm'
include 'decryptionrounds.asm'
include 'galois.asm'

;encrypts cleartext and stores the result at enctext
proc encAES size:DWORD, cleartext_ptr:DWORD, enctext_ptr:DWORD,\
     aeskey_ptr:DWORD

local keychain[(ENCRYPTION_ROUNDS+1)*BLOCK_SIZE]:BYTE, sbox[SBOX_SIZE]:BYTE,\
      rcon[RCON_SIZE]:BYTE, galois_mul2[GALOIS_SIZE]:BYTE,\
      galois_mul3[GALOIS_SIZE]:BYTE, mul2_table_ptr:DWORD,\
      mul3_table_ptr:DWORD, sbox_ptr:DWORD, keychain_ptr:DWORD,\
      rcon_ptr:DWORD

    pushad
    ;sbox and rcon are created in memory
    ;galois lookup tables too
    lea eax,[sbox]
    mov [sbox_ptr], eax
    stdcall createSBox, eax
    lea eax,[rcon]
    mov [rcon_ptr], eax
    stdcall createRcon, eax
    lea eax,[galois_mul2]
    mov [mul2_table_ptr], eax
    lea ebx,[galois_mul3]
    mov [mul3_table_ptr], ebx
    stdcall createGaloisEncryption, eax, ebx

    ;copy the key into the round key buffer
    mov ecx, KEY_SIZE
    mov esi, [aeskey_ptr]
    lea edi, [keychain]
    mov [keychain_ptr], edi
    rep movsb

    ;create the round keys
    stdcall createKeyChain, [keychain_ptr], [sbox_ptr],\
	    [rcon_ptr]

    ;copy clear text to encryption buffer
    mov ecx, [size]
    mov esi, [cleartext_ptr]
    mov edi, [enctext_ptr]
    rep movsb

    ;eax == current to be encrypted block
    ;ebx == end of cleartext
    mov eax,[enctext_ptr]
    mov ebx,eax
    add ebx,[size]
eaes_block_loop:
    stdcall encryptionRounds, eax, [keychain_ptr], \
	    [sbox_ptr], [mul2_table_ptr], [mul3_table_ptr]

    add eax,BLOCK_SIZE
    cmp eax,ebx
    jnge eaes_block_loop

    popad
    mov eax,1
    ret

endp

;decrypts cleartext and stores the result at enctext
proc decAES size:DWORD, enctext_ptr:DWORD, cleartext_ptr:DWORD,\
     aeskey_ptr:DWORD

local keychain[(ENCRYPTION_ROUNDS+1)*BLOCK_SIZE]:BYTE,\
      sbox[SBOX_SIZE]:BYTE, invert_sbox[SBOX_SIZE]:BYTE,\
      rcon[RCON_SIZE]:BYTE,\
      galois_mul9[GALOIS_SIZE]:BYTE, galois_mul11[GALOIS_SIZE]:BYTE, \
      galois_mul13[GALOIS_SIZE]:BYTE, galois_mul14[GALOIS_SIZE]:BYTE,\
      mul9_table_ptr:DWORD, mul11_table_ptr:DWORD, mul13_table_ptr:DWORD,\
      mul14_table_ptr:DWORD, sbox_ptr:DWORD, invert_sbox_ptr:DWORD,\
      keychain_ptr:DWORD, rcon_ptr:DWORD

    pushad
    ;sbox, invert sbox
    ;and rcon are created in memory
    lea eax,[sbox]
    mov [sbox_ptr], eax
    stdcall createSBox, eax
    lea eax,[rcon]
    mov [rcon_ptr], eax
    stdcall createRcon, eax
    lea eax, [invert_sbox]
    mov [invert_sbox_ptr], eax
    stdcall createInvertSBox, eax

    ;create galois lookup tables for
    ;9, 11, 13 and 14
    lea eax,[galois_mul9]
    mov [mul9_table_ptr], eax
    lea ebx,[galois_mul11]
    mov [mul11_table_ptr], ebx
    lea ecx,[galois_mul13]
    mov [mul13_table_ptr], ecx
    lea edx,[galois_mul14]
    mov [mul14_table_ptr], edx
    stdcall createGaloisDecryption, eax, ebx, ecx, edx

    ;copy the key into the round key buffer
    mov ecx, KEY_SIZE
    mov esi, [aeskey_ptr]
    lea edi, [keychain]
    mov [keychain_ptr], edi
    rep movsb

    ;create the round keys
    stdcall createKeyChain, [keychain_ptr], [sbox_ptr],\
	    [rcon_ptr]

    ;copy encrypted text to decryption buffer
    mov ecx, [size]
    mov esi, [enctext_ptr]
    mov edi, [cleartext_ptr]
    rep movsb

    ;eax == current to be decrypted block
    ;ebx == end of cleartext
    mov eax,[cleartext_ptr]
    mov ebx,eax
    add ebx,[size]
daes_block_loop:
    stdcall decryptionRounds, eax, [keychain_ptr],\
	    [invert_sbox_ptr], [mul9_table_ptr], [mul11_table_ptr],\
	    [mul13_table_ptr], [mul14_table_ptr]

    add eax,BLOCK_SIZE
    cmp eax,ebx
    jnge daes_block_loop

    popad
    mov eax,1
    ret

endp