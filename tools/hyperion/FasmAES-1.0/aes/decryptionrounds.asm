;uses the generated round keys to decrypt an aes block
proc decryptionRounds decryption_ptr:DWORD,\
     roundkeys_ptr:DWORD, inverse_sbox_ptr:DWORD, mul9_table_ptr:DWORD, \
     mul11_table_ptr:DWORD, mul13_table_ptr:DWORD,\
     mul14_table_ptr:DWORD

    pushad

    ;roundkey and decryption in eax and ebx
    mov eax, [roundkeys_ptr]
    add eax, BLOCK_SIZE*ENCRYPTION_ROUNDS
    mov ebx, [decryption_ptr]

    ;final round
    stdcall addRoundKey, ebx, eax
    stdcall inverseShiftRows, ebx
    stdcall subBlockBytes, ebx, [inverse_sbox_ptr]
    sub eax,BLOCK_SIZE

    ;main round
dr_main:
    stdcall addRoundKey, ebx, eax
    stdcall mixColumns9111314, ebx, [mul9_table_ptr], [mul11_table_ptr],\
	    [mul13_table_ptr], [mul14_table_ptr]
    stdcall inverseShiftRows, ebx
    stdcall subBlockBytes, ebx, [inverse_sbox_ptr]
    sub eax, BLOCK_SIZE
    cmp eax, [roundkeys_ptr]
    jne dr_main

    ;initial_round
    stdcall addRoundKey, ebx, eax

    popad
    ret
endp

;mix columns operation is a column matrix
;multiplication
proc mixColumns9111314, data_ptr:DWORD, mul9_table_ptr:DWORD,\
     mul11_table_ptr:DWORD, mul13_table_ptr:DWORD, mul14_table_ptr:DWORD

     local current_column:DWORD

    push edx
    push eax
    push ebx
    push ecx
    mov edx, [data_ptr]

    rept 4{
    ;element 3
    mov eax, [edx]
    mov ebx, [mul9_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov ebx, [mul13_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov ebx, [mul11_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov ebx, [mul14_table_ptr]
    xlatb
    xor cl, al
    mov [current_column], ecx
    ;element 2
    mov eax, [edx]
    mov ebx, [mul13_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov ebx, [mul11_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov ebx, [mul14_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov ebx, [mul9_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 1
    mov eax, [edx]
    mov ebx, [mul11_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov ebx, [mul14_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov ebx, [mul9_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov ebx, [mul13_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 0
    mov eax, [edx]
    mov ebx, [mul14_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov ebx, [mul9_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov ebx, [mul13_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov ebx, [mul11_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    ;finished, store it
    mov [edx], eax
    add edx, COLUMN_SIZE
    }

    pop ecx
    pop ebx
    pop eax
    pop edx
    ret

endp

;reverse shift operation for decryption
proc inverseShiftRows, data_ptr:DWORD

    push eax
    push ebx
    mov ebx,[data_ptr]

    loadRow
    rol eax, 8
    storeRow
    inc ebx
    loadRow
    rol eax, 16
    storeRow
    inc ebx
    loadRow
    rol eax, 24
    storeRow

    pop ebx
    pop eax
    ret

endp