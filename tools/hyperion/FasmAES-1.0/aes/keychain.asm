;creates the round keys in keychain_ptr
if defined AES128
proc createKeyChain keychain_ptr:DWORD, sbox_ptr:DWORD,\
		    rcon_ptr:DWORD

local current_row:DWORD

     ;current column in ecx
     mov ecx, ROW_SIZE-1
     ;current rcon index in edx
     mov edx, 1

key_schedule_round:
     ;-------------------
     ;get current column, apply key schedule core and
     ;xor the result with ecx-ROW_SIZE-1
     stdcall loadColumn, [keychain_ptr], ecx
     ;shift rows
     rol eax,8
     ;substitute with sbox
     stdcall subBytes, eax, [sbox_ptr]
     ;xor with rcon
     stdcall xorRcon, eax, [rcon_ptr], edx
     inc edx
     ;xor with column at index-ROW_SIZE-1
     mov ebx,eax
     push ecx
     sub ecx,ROW_SIZE-1
     stdcall loadColumn, [keychain_ptr],ecx
     pop ecx
     xor eax,ebx
     ;store at index+1
     inc ecx
     stdcall storeColumn, eax, [keychain_ptr], ecx
     ;-------------------

     ;-------------------
     ;three times: get current column and
     ;xor it with ecx-ROW_SIZE-1
     rept 3{
	  stdcall loadColumn, [keychain_ptr], ecx ;can be removed
	  mov ebx, eax
	  push ecx
	  sub ecx,ROW_SIZE-1
	  stdcall loadColumn, [keychain_ptr],ecx
	  pop ecx
	  xor eax,ebx
	  inc ecx
	  stdcall storeColumn, eax, [keychain_ptr], ecx
     }
     ;-------------------

     ;check for end of keychain generation
     cmp ecx, EXTENDED_KEY_SIZE/COLUMN_SIZE - 1
     jne key_schedule_round

     ret
endp
end if

if defined AES192
proc createKeyChain keychain_ptr:DWORD, sbox_ptr:DWORD,\
		    rcon_ptr:DWORD

local current_row:DWORD

     ;current column in ecx
     mov ecx, ROW_SIZE-1
     ;current rcon index in edx
     mov edx, 1

key_schedule_round:
     ;-------------------
     ;get current column, apply key schedule core and
     ;xor the result with ecx-ROW_SIZE-1
     stdcall loadColumn, [keychain_ptr], ecx
     ;shift rows
     rol eax,8
     ;substitute with sbox
     stdcall subBytes, eax, [sbox_ptr]
     ;xor with rcon
     stdcall xorRcon, eax, [rcon_ptr], edx
     inc edx
     ;xor with column at index-ROW_SIZE-1
     mov ebx,eax
     push ecx
     sub ecx,ROW_SIZE-1
     stdcall loadColumn, [keychain_ptr],ecx
     pop ecx
     xor eax,ebx
     ;store at index+1
     inc ecx
     stdcall storeColumn, eax, [keychain_ptr], ecx
     ;-------------------

     ;-------------------
     ;three times: get current column and
     ;xor it with ecx-ROW_SIZE-1
     rept 3{
	  stdcall loadColumn, [keychain_ptr], ecx ;can be removed
	  mov ebx, eax
	  push ecx
	  sub ecx,ROW_SIZE-1
	  stdcall loadColumn, [keychain_ptr],ecx
	  pop ecx
	  xor eax,ebx
	  inc ecx
	  stdcall storeColumn, eax, [keychain_ptr], ecx
     }
     ;-------------------

     ;check for end of keychain generation
     cmp ecx, EXTENDED_KEY_SIZE/COLUMN_SIZE - 1
     je exit_key_schedule_round

     ;-------------------
     ;two times: get current column and
     ;xor it with ecx-ROW_SIZE-1
     rept 2{
	  stdcall loadColumn, [keychain_ptr], ecx ;can be removed
	  mov ebx, eax
	  push ecx
	  sub ecx,ROW_SIZE-1
	  stdcall loadColumn, [keychain_ptr],ecx
	  pop ecx
	  xor eax,ebx
	  inc ecx
	  stdcall storeColumn, eax, [keychain_ptr], ecx
     }
     ;-------------------

     jmp key_schedule_round

exit_key_schedule_round:
     ret
endp
end if

if defined AES256
proc createKeyChain keychain_ptr:DWORD, sbox_ptr:DWORD,\
		    rcon_ptr:DWORD

local current_row:DWORD

     ;current column in ecx
     mov ecx, ROW_SIZE-1
     ;current rcon index in edx
     mov edx, 1

key_schedule_round:
     ;-------------------
     ;get current column, apply key schedule core and
     ;xor the result with ecx-ROW_SIZE-1
     stdcall loadColumn, [keychain_ptr], ecx
     ;shift rows
     rol eax,8
     ;substitute with sbox
     stdcall subBytes, eax, [sbox_ptr]
     ;xor with rcon
     stdcall xorRcon, eax, [rcon_ptr], edx
     inc edx
     ;xor with column at index-ROW_SIZE-1
     mov ebx,eax
     push ecx
     sub ecx,ROW_SIZE-1
     stdcall loadColumn, [keychain_ptr],ecx
     pop ecx
     xor eax,ebx
     ;store at index+1
     inc ecx
     stdcall storeColumn, eax, [keychain_ptr], ecx
     ;-------------------

     ;-------------------
     ;three times: get current column and
     ;xor it with ecx-ROW_SIZE-1
     rept 3{
	  stdcall loadColumn, [keychain_ptr], ecx ;can be removed
	  mov ebx, eax
	  push ecx
	  sub ecx,ROW_SIZE-1
	  stdcall loadColumn, [keychain_ptr],ecx
	  pop ecx
	  xor eax,ebx
	  inc ecx
	  stdcall storeColumn, eax, [keychain_ptr], ecx
     }
     ;-------------------

     ;check for end of keychain generation
     cmp ecx, EXTENDED_KEY_SIZE/COLUMN_SIZE - 1
     je exit_key_schedule_round

     ;-------------------
     ;one times: get current column, subsitute with
     ;sbox and xor it with ecx-ROW_SIZE-1
     ;three times: get current column and
     ;xor it with ecx-ROW_SIZE-1
     stdcall loadColumn, [keychain_ptr], ecx ;can be removed
     stdcall subBytes, eax, [sbox_ptr]
     mov ebx, eax
     push ecx
     sub ecx,ROW_SIZE-1
     stdcall loadColumn, [keychain_ptr],ecx
     pop ecx
     xor eax,ebx
     inc ecx
     stdcall storeColumn, eax, [keychain_ptr], ecx
     ;three times
     rept 3{
	  stdcall loadColumn, [keychain_ptr], ecx ;can be removed
	  mov ebx, eax
	  push ecx
	  sub ecx,ROW_SIZE-1
	  stdcall loadColumn, [keychain_ptr],ecx
	  pop ecx
	  xor eax,ebx
	  inc ecx
	  stdcall storeColumn, eax, [keychain_ptr], ecx
     }
     ;-------------------

     jmp key_schedule_round

exit_key_schedule_round:
     ret
endp
end if

;store a column at column_index in keychain
proc storeColumn column:DWORD, keychain_ptr:DWORD, column_index:DWORD
     push eax
     push ebx
     push edx

     ;create pointer to first byte of the column
     ;and store column there
     mov eax, [column_index]
     mov ebx, COLUMN_SIZE
     mul ebx
     add eax, [keychain_ptr]
     mov ebx, [column]
     mov [eax], ebx

     pop edx
     pop ebx
     pop eax
     ret
endp

;xor key dword with (rcon(index) 00 00 00)
proc xorRcon key:DWORD, rcon_ptr:DWORD, rcon_index:DWORD
     push ebx
     mov eax,[rcon_index]
     mov ebx,[rcon_ptr]
     xlatb
     shl eax,24
     mov ebx,[key]
     xor eax,ebx
     pop ebx
     ret
endp

;returns in eax the column at column_index in the key chain
proc loadColumn keychain_ptr:DWORD, column_index:DWORD
     push ebx
     push edx
     ;create pointer to first byte of the colum
     mov eax, [column_index]
     mov ebx, COLUMN_SIZE
     mul ebx
     add eax, [keychain_ptr]
     ;return dword and exit
     mov eax,[eax]
     pop edx
     pop ebx
     ret
endp

;substitute subkey's bytes with the sbox
proc subBytes subkey:DWORD, sbox_ptr:DWORD
     push ebx
     mov eax, [subkey]
     mov ebx, [sbox_ptr]
     xlatb
     ror eax, 8
     xlatb
     ror eax, 8
     xlatb
     ror eax, 8
     xlatb
     ror eax, 8
     pop ebx
     ret
endp