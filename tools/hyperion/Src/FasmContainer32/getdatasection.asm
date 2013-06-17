;Returns a pointer to the image base
proc getImageBase stdcall APITable:DWORD

local str1[256]:BYTE, retval:DWORD

	pushad
	;write to logfile
	mov [retval],1
	createStringImageBase str1
	lea eax,[str1]
	stdcall writeLog, [APITable], eax
	test eax,eax
	jz gib_exit_error
	stdcall writeNewLineToLog, [APITable]
	test eax,eax
	jz gib_exit_error

	;receive image base
	mov ebx,[APITable]
	stdcall dword [ebx+GetModuleHandle],0
	test eax,eax
	jz gib_exit_error
	mov [retval],eax
	stdcall writeRegisterToLog, [APITable], eax
	test eax,eax
	jz gib_exit_error
	popad
	mov eax,[retval]
	ret

gib_exit_error:
	popad
	mov eax,0
	ret

endp

;Returns a pointer to the data section header
proc getDataSection stdcall APITable:DWORD, image_base:DWORD

local str1[256]:BYTE, retval:DWORD, file_header:DWORD,\
numbers_of_sections:DWORD, optional_header:DWORD,\
current_section_name[9]:BYTE, current_section:DWORD

	pushad
	;find PE header
	mov ebx,[image_base]
	mov ax,[ebx+IMAGE_DOS_HEADER.e_magic]
	cmp ax,IMAGE_DOS_SIGNATURE
	jne gds_exit_error
	mov edx,[ebx+IMAGE_DOS_HEADER.e_lfanew]
	add edx,ebx
	mov eax,dword [edx]
	cmp eax,IMAGE_NT_SIGNATURE
	jne gds_exit_error
	writeWithNewLine createStringFoundPE, str1, gds_exit_error
	add edx,4
	mov [file_header],edx

	;get sections amount and check characteristics
	sub eax,eax
	mov ax,[edx+IMAGE_FILE_HEADER.NumberOfSections]
	mov [numbers_of_sections],eax
	sub eax,eax
	mov ax,[edx+IMAGE_FILE_HEADER.Characteristics]
	mov ebx,eax
	and ebx,IMAGE_FILE_EXECUTABLE_IMAGE
	test ebx,ebx
	jz gds_exit_error
	mov ebx,eax
	and ebx,IMAGE_FILE_DLL
	test ebx,ebx
	jnz gds_exit_error
	writeWithNewLine createStringCharacteristicsOK, str1, gds_exit_error

	;check optional header
	add edx,sizeof.IMAGE_FILE_HEADER
	mov [optional_header],edx
	mov ax,[edx+IMAGE_OPTIONAL_HEADER32.Magic]
	cmp ax,IMAGE_NT_OPTIONAL_HDR32_MAGIC
	jne gds_exit_error
	writeWithNewLine createStringFoundPE32, str1, gds_exit_error

	;jump to section headers
	lea ebx,[edx+IMAGE_OPTIONAL_HEADER32.DataDirectory]
	mov eax,[edx+IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes]
	mov edx,sizeof.IMAGE_DATA_DIRECTORY
	mul edx
	add eax,ebx

	;find data section
	createStringDataSection str1
	mov [current_section],0
	;eax contains pointer to current section
gds_check_section:
	;copy section name into 9 byte buffer
	lea edi,[current_section_name]
	mov byte [edi+8],0
	mov esi,eax
	mov ecx,8
	rep movsb
	;check whether current section name
	;has a length of SIZE_DATA_SECTION_NAME
	mov ebx,eax
	lea eax,[current_section_name]
	stdcall strlen,eax
	cmp eax,SIZE_DATA_SECTION_NAME
	jne gds_not_data_section
	;compare current section name with
	;the string ".data"
	lea edi,[current_section_name]
	lea esi,[str1]
	mov ecx,SIZE_DATA_SECTION_NAME
	rep cmpsb
	jnz gds_not_data_section
	;found data section, pointer in ebx
	jmp gds_data_section

gds_not_data_section:
	;end of section headers?
	inc [current_section]
	mov eax,[current_section]
	cmp eax,[numbers_of_sections]
	jae gds_exit_error
	;check next section
	mov eax,ebx
	add eax,sizeof.IMAGE_SECTION_HEADER
	jmp gds_check_section

gds_data_section:
	;data section header in ebx
	writeWithNewLine createStringFoundDataSection, str1, gds_exit_error
	mov [retval],ebx

gds_exit:
	popad
	mov eax,[retval]
	ret

gds_exit_error:
	popad
	mov eax,0
	ret

endp