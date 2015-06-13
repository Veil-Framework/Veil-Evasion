;Decrypt the exe which is stored in the data section
proc decryptExecutable stdcall APITable:DWORD, image_base:DWORD, section_header:DWORD

local str1[256]:BYTE, ret_val:DWORD, section_address:DWORD,\
section_size:DWORD, key[KEY_SIZE]:BYTE, encrypted_backup:DWORD

	pushad
	;get section adress and size
	stdcall writeNewLineToLog, [APITable]
	writeWithNewLine createStringDecrypting, str1, dec_exit_error
	mov eax,[image_base]
	mov ebx,[section_header]
	mov edx,[ebx+IMAGE_SECTION_HEADER.VirtualSize]
	mov [section_size],edx
	mov edx,[ebx+IMAGE_SECTION_HEADER.VirtualAddress]
	add eax,edx
	mov [section_address],eax

	;init key
	lea edi,[key]
	mov ecx, KEY_SIZE
	mov al,0
dec_init_key:
	mov [edi],al
	inc edi
	dec ecx
	jnz dec_init_key

	;create a copy of the encrypted file
	;which is used to brute force the key
	mov eax,[APITable]
	stdcall dword [eax+VirtualAlloc], 0, [section_size], MEM_COMMIT+MEM_RESERVE, PAGE_READWRITE
	test eax, eax
	jz dec_exit_error
	mov [encrypted_backup],eax
	;now copy the file into the buffer
	mov edi,eax
	mov esi,[section_address]
	mov ecx,[section_size]
	;we can mov dwords because buffer is a multiple of 16
	shr ecx,2
	repz movsd

keyspace_loop:
	lea eax,[key]
	stdcall decAES, [section_size],  [section_address],  [section_address], eax
	stdcall verifyChecksum, [section_address], [section_size]
	test eax,eax
	jnz dec_decrypted_success

	;restore the encrypted version to try the next key
	mov esi,[encrypted_backup]
	mov edi,[section_address]
	mov ecx,[section_size]
	shr ecx,2
	repz movsd
	;lea eax,[key]
	;stdcall encAES, [section_size],  [section_address],  [section_address], eax

	;next key
	lea eax,[key]
	stdcall nextKey, eax
	test eax,eax
	jz dec_exit_error
	;abort if key space was explored, else continue
	jmp keyspace_loop

dec_decrypted_success:
	mov eax,[APITable]
	stdcall dword [eax+VirtualFree], [encrypted_backup], 0, MEM_RELEASE
	test eax, eax
	jz dec_exit_error

dec_exit_success:
	popad
	mov eax,1
	ret

dec_exit_error:
	popad
	sub eax,eax
	ret

endp

;xor encryption
proc encryptXOR stdcall data_ptr:DWORD, data_size:DWORD, key_ptr:DWORD

local key_counter:DWORD

	pushad
	mov [key_counter],0
	mov edi,[data_ptr]
encxor_loop:
	;get key, data and xor it
	mov eax,[key_ptr]
	add eax,[key_counter]
	mov bl,byte [eax]
	mov bh,byte [edi]
	xor bh,bl
	mov [edi],bh
	;increase counter variables
	mov eax,[key_counter]
	inc eax
	cmp eax,KEY_SIZE
	jne encxor_noreset_keycounter
	sub eax,eax
encxor_noreset_keycounter:
	mov [key_counter],eax
	;increase data ptr
	mov eax,[data_size]
	dec eax
	jz encxor_exit
	mov [data_size],eax
	inc edi
	jmp encxor_loop

encxor_exit:
	popad
	ret
endp

;generate next decryption key
proc nextKey stdcall key_ptr:DWORD

	push ebx
	mov eax,[key_ptr]
	mov ebx,eax
	add ebx,REAL_KEY_SIZE
nkey_next_element:
	inc byte [eax]
	cmp byte [eax],REAL_KEY_RANGE
	jne nkey_not_finished
	mov byte [eax],0
	inc eax
	cmp eax,ebx
	je nkey_finished
	jmp nkey_next_element

nkey_not_finished:
	pop ebx
	mov eax,1
	ret

nkey_finished:
	pop ebx
	sub eax,eax
	ret

endp;