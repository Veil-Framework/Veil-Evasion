;Loads the exe which is stored in input_image
;into memory and starts its execution
proc loadExecutable stdcall APITable:DWORD,\
input_image:DWORD

local str1[256]:BYTE, ret_val:DWORD, image_file_header:DWORD,\
loaded_file:DWORD

	pushad
	;verify checksum of packed executable
	writeWithNewLine createStringVerifyChecksum, str1, le_exit_error
	stdcall verifyChecksum, [input_image], INFILE_SIZE
	test eax,eax
	jz le_exit_error

	;verify whether the content of the data section is pe
	writeWithNewLine createStringVerifyPE, str1, le_exit_error
	mov eax,[input_image]
	add eax,4
	stdcall verifyPE, eax, INFILE_SIZE
	test eax,eax
	mov [image_file_header],eax
	jz le_exit_error

	;copy pe header and sections into memory
	writeNewLineToLog APITable
	writeWithNewLine createStringMappingFileInMemory, str1, le_exit_error
	mov eax,[input_image]
	add eax,4
	mov ebx,INFILE_SIZE
	sub ebx,4
	stdcall loadFile, [APITable], [image_file_header], eax, ebx
	test eax,eax
	mov [loaded_file],eax
	jz le_exit_error

	;loading import table
	writeNewLineToLog APITable
	writeWithNewLine createStringLoadingFilesAPIs, str1, le_exit_error
	stdcall loadImportTable, [APITable], [loaded_file]
	test eax,eax
	jz le_exit_error

	;set the correct permissions for each section
	writeNewLineToLog APITable
	writeWithNewLine createStringSettingPermissions, str1, le_exit_error
	mov eax,[input_image]
	add eax,4
	mov ebx,INFILE_SIZE
	sub ebx,4
	stdcall setPermissions, [APITable], [image_file_header], eax, ebx
	test eax,eax
	jz le_exit_error

le_exit_success:
	popad
	mov eax,1
	ret

le_exit_error:
	popad
	mov eax,0
	ret

endp

;load the APIs in the import table
proc loadImportTable, APITable:DWORD, image_base:DWORD

local str1[256]:BYTE, import_table:DWORD, null_directory_entry[sizeof.IMAGE_IMPORT_DESCRIPTOR]:BYTE

	pushad
	;find import table in data directory
	mov edx,[image_base]
	mov eax,[edx+IMAGE_DOS_HEADER.e_lfanew]
	add eax,edx
	add eax,4
	;image file header now in eax
	add eax,sizeof.IMAGE_FILE_HEADER
	lea eax,[eax+IMAGE_OPTIONAL_HEADER32.DataDirectory]
	;first data directory entry now in eax
	add eax,sizeof.IMAGE_DATA_DIRECTORY
	;import data directory entry now in eax
	mov eax,[eax+IMAGE_DATA_DIRECTORY.VirtualAddress]
	add eax,edx
	;pointer to import table now in eax
	mov [import_table],eax
	writeWithNewLine createStringFoundImportTable, str1, le_exit_error
	writeRegisterToLog APITable, [import_table]
	test eax,eax
	jz pit_exit_error

	;init null directory entry
	lea esi,[null_directory_entry]
	mov ecx,sizeof.IMAGE_IMPORT_DESCRIPTOR
	mov al,0
pit_init_null_directory_loop:
	mov [esi],al
	inc esi
	dec ecx
	jnz pit_init_null_directory_loop

	mov ebx,[import_table]
	;iterate over the directory tables
pit_next_directory_entry:
	lea esi,[null_directory_entry]
	mov edi,ebx
	mov ecx,sizeof.IMAGE_IMPORT_DESCRIPTOR
	rep cmpsb
	je pit_exit_success
	;load APIs of this directory
	stdcall loadImportDirectoryTable, [APITable], [image_base], ebx
	test eax,eax
	jz pit_exit_error
	;next entry
	add ebx,sizeof.IMAGE_IMPORT_DESCRIPTOR
	jmp pit_next_directory_entry

pit_exit_success:
	popad
	mov eax,1
	ret

pit_exit_error:
	popad
	mov eax,0
	ret
endp

;loads the APIs
proc loadImportDirectoryTable stdcall, APITable:DWORD, image_base:DWORD, directory_entry:DWORD

local str1[256]:BYTE, lookup_table:DWORD, import_address_table:DWORD, dll_image_base:DWORD

	pushad
	;write info about data directory table to logfile
	writeNewLineToLog APITable
	test eax,eax
	jz lidt_exit_error
	writeWithNewLine createStringProcessImportDirectory, str1, lidt_exit_error
	mov eax,[directory_entry]
	mov eax,[eax+IMAGE_IMPORT_DESCRIPTOR.Name_]
	add eax,[image_base]
	mov ebx,eax
	;pointer to dll name in ebx
	writeLog APITable, eax
	test eax,eax
	jz lidt_exit_error
	writeNewLineToLog APITable
	test eax,eax
	jz lidt_exit_error

	;load the corresponding dll
	invoke LoadLibrary, ebx
	test eax,eax
	jz lidt_exit_error
	mov [dll_image_base],eax

	;read pointer to the api tables
	mov edx,[directory_entry]
	mov eax,[edx+IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk]
	add eax,[image_base]
	mov [lookup_table],eax
	mov eax,[edx+IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
	add eax,[image_base]
	mov [import_address_table],eax

	;index to current API
	sub ecx,ecx
	;iterate the lookup_table entries
lidt_next_lookup_entry:
	mov eax,[lookup_table]
	add eax,ecx
	mov eax,[eax]
	test eax,eax
	jz lidt_exit_success
	mov ebx,eax
	and eax,IMAGE_ORDINAL_FLAG32
	jnz lidt_byordinal
lidt_byname:
	createStringName str1
	lea eax,[str1]
	writeLog APITable, eax
	test eax,eax
	jz lidt_exit_error
	add ebx,[image_base]
	lea ebx,[ebx+IMAGE_IMPORT_BY_NAME.Name_]
	mov eax,ebx
	writeLog APITable, eax
	test eax,eax
	jz lidt_exit_error
	writeNewLineToLog APITable
	test eax,eax
	jz lidt_exit_error
	;API name pointer in ebx
	push ecx
	invoke GetProcAddress, [dll_image_base], ebx
	pop ecx
	test eax,eax
	jz lidt_exit_error
	mov ebx,[import_address_table]
	add ebx,ecx
	mov [ebx],eax
	;fetch next API
	add ecx,4
	jmp lidt_next_lookup_entry

lidt_byordinal:
	createStringOrdinal str1
	lea eax,[str1]
	writeLog APITable, eax
	test eax,eax
	jz lidt_exit_error
	;remove the ordinal flag
	xor ebx,IMAGE_ORDINAL_FLAG32
	mov eax,ebx
	writeRegisterToLog APITable, eax
	test eax,eax
	jz pit_exit_error
	;API ordinal in ebx
	push ecx
	invoke GetProcAddress, [dll_image_base], ebx
	pop ecx
	test eax,eax
	jz lidt_exit_error
	mov ebx,[import_address_table]
	add ebx,ecx
	mov [ebx],eax
	;fetch next API
	add ecx,4
	jmp lidt_next_lookup_entry

lidt_exit_success:
	popad
	mov eax,1
	ret

lidt_exit_error:
	popad
	mov eax,0
	ret
endp;

;sets the memory permissions for each section
proc setPermissions stdcall, APITable:DWORD, image_file_header:DWORD, file_image_base:DWORD, \
file_image_size:DWORD

local number_of_sections:DWORD, image_base:DWORD, section_headers:DWORD,\
pe_header_size:DWORD, str1[256]:BYTE, vprotect_ret:DWORD

	pushad
	;find section header
	mov edx,[image_file_header]
	sub eax,eax
	mov ax,[edx+IMAGE_FILE_HEADER.NumberOfSections]
	mov [number_of_sections],eax
	add edx,sizeof.IMAGE_FILE_HEADER
	mov eax,[edx+IMAGE_OPTIONAL_HEADER32.ImageBase]
	mov [image_base],eax
	;search for section header
	lea ebx,[edx+IMAGE_OPTIONAL_HEADER32.DataDirectory]
	mov eax,[edx+IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes]
	mov edx,sizeof.IMAGE_DATA_DIRECTORY
	mul edx
	add eax,ebx
	;first section header found
	mov [section_headers],eax
	mov eax,sizeof.IMAGE_SECTION_HEADER
	mov edx,[number_of_sections]
	mul edx
	;end of section header sections found
	add eax,[section_headers]
	mov ebx,[file_image_base]
	sub eax,ebx
	;unaligned size of pe header in eax
	mov [pe_header_size],eax

	;set pe header page read-only
	mov edx,[APITable]
	lea eax,[vprotect_ret]
	stdcall dword [edx+VirtualProtect], [image_base], [pe_header_size], PAGE_READONLY, eax
	test eax,eax
	jz sp_exit_error

	;some output for the user
	writeRegisterToLog APITable, [image_base]
	test eax,eax
	jz sp_exit_error

	;set the section page permissions
	mov ecx,[number_of_sections]
	mov ebx,[section_headers]
sp_load_section_loop:
	stdcall setSection, [APITable], ebx, [image_base], [file_image_base]
	test eax,eax
	jz sp_exit_error
	add ebx,sizeof.IMAGE_SECTION_HEADER
	dec ecx
	jnz sp_load_section_loop

sp_exit_success:
	popad
	mov eax,1
	ret

sp_exit_error:
	popad
	sub eax,eax
	ret
endp;

;sets the complete image of the decrypted file writeable so
;we can copy pe header and sections into into
proc loadFile stdcall, APITable:DWORD, image_file_header:DWORD, file_image_base:DWORD, \
file_image_size:DWORD

local number_of_sections:DWORD, image_base:DWORD, aux:DWORD,\
str1[256]:BYTE, vprotect_ret:DWORD, section_headers:DWORD, pe_header_size:DWORD

	pushad
	;find section header
	mov edx,[image_file_header]
	sub eax,eax
	mov ax,[edx+IMAGE_FILE_HEADER.NumberOfSections]
	mov [number_of_sections],eax
	add edx,sizeof.IMAGE_FILE_HEADER
	mov eax,[edx+IMAGE_OPTIONAL_HEADER32.ImageBase]
	mov [image_base],eax
	;make the complete image writable
	mov eax,[edx+IMAGE_OPTIONAL_HEADER32.SizeOfImage]
	mov [aux],edx ;store edx, we need it later
	lea edx,[vprotect_ret]
	mov ebx,[APITable]
	stdcall dword [ebx+VirtualProtect], [image_base], eax, PAGE_READWRITE, edx
	test eax,eax
	jz lf_exit_error

	;some output for the user
	writeWithNewLine createStringLoadedPEHeader, str1, lf_exit_error
	writeRegisterToLog APITable, [image_base]
	test eax,eax
	jz lf_exit_error

	mov edx,[aux] ;restore edx
	;continue search for section header
	lea ebx,[edx+IMAGE_OPTIONAL_HEADER32.DataDirectory]
	mov eax,[edx+IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes]
	mov edx,sizeof.IMAGE_DATA_DIRECTORY
	mul edx
	add eax,ebx

	;first section header found
	mov [section_headers],eax
	mov eax,sizeof.IMAGE_SECTION_HEADER
	mov edx,[number_of_sections]
	mul edx
	;end of section header sections found
	add eax,[section_headers]
	mov ebx,[file_image_base]
	sub eax,ebx
	;unaligned size of pe header in eax
	mov [pe_header_size],eax

	;copy header to memory
	mov edi,[image_base]
	mov esi,[file_image_base]
	mov ecx,[pe_header_size]
	rep movsb

	;load the sections
	mov ecx,[number_of_sections]
	mov ebx,[section_headers]
lf_load_section_loop:
	stdcall loadSection, [APITable], ebx, [image_base], [file_image_base]
	test eax,eax
	jz lf_exit_error
	add ebx,sizeof.IMAGE_SECTION_HEADER
	dec ecx
	jnz lf_load_section_loop

lf_exit_success:
	popad
	mov eax,[image_base]
	ret

lf_exit_error:
	popad
	mov eax,0
	ret

endp

;load the corresponding section into memory
proc loadSection stdcall, APITable:DWORD, section_header:DWORD, image_base:DWORD,\
file_image_base:DWORD

local str1[256]:BYTE

	pushad
	;copy from file into memory
	mov edx,[section_header]
	mov edi,[edx+IMAGE_SECTION_HEADER.VirtualAddress]
	add edi,[image_base]
	mov esi,[file_image_base]
	add esi,[edx+IMAGE_SECTION_HEADER.PointerToRawData]
	mov ecx,[edx+IMAGE_SECTION_HEADER.SizeOfRawData]
	rep movsb

	;print some infos to the log file
	createStringLoaded str1
	lea eax,[str1]
	writeLog APITable, eax
	test eax,eax
	jz ls_exit_error
	lea edi,[str1]
	mov byte [edi+8],0
	mov edx,[section_header]
	lea esi,[edx+IMAGE_SECTION_HEADER._Name]
	mov ecx,8
	push edi
	rep movsb
	pop edi
	writeLog APITable, edi
	writeNewLineToLog APITable
	mov edx,[section_header]
	mov eax,[edx+IMAGE_SECTION_HEADER.VirtualAddress]
	add eax,[image_base]
	writeRegisterToLog APITable, eax

ls_exit_success:
	popad
	mov eax,1
	ret

ls_exit_error:
	popad
	sub eax,eax
	ret

endp

;set the memory page permission for the corresponding section
proc setSection stdcall, APITable:DWORD, section_header:DWORD, image_base:DWORD,\
file_image_base:DWORD

local section_flags:DWORD, vprotect_ret:DWORD, str1[256]:BYTE

	pushad
	mov edx,[section_header]
;section execute/read/write?
	mov ebx,[edx+IMAGE_SECTION_HEADER.Characteristics]
	and ebx,IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
	cmp ebx,IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
	jne ssn_no_execute_read_write
	mov eax,PAGE_EXECUTE_READWRITE
	mov [section_flags],eax
	jmp ssn_set_memory
ssn_no_execute_read_write:
	;section execute/read?
	mov ebx,[edx+IMAGE_SECTION_HEADER.Characteristics]
	and ebx,IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ
	cmp ebx,IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ
	jne ssn_no_execute_read
	mov eax,PAGE_EXECUTE_READ
	mov [section_flags],eax
	jmp ssn_set_memory
ssn_no_execute_read:
	;section read/write?
	mov ebx,[edx+IMAGE_SECTION_HEADER.Characteristics]
	and ebx,IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
	cmp ebx,IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
	jne ssn_no_read_write
	mov eax,PAGE_READWRITE
	mov [section_flags],eax
	jmp ssn_set_memory
ssn_no_read_write:
	;section read?
	mov ebx,[edx+IMAGE_SECTION_HEADER.Characteristics]
	and ebx,IMAGE_SCN_MEM_READ
	cmp ebx,IMAGE_SCN_MEM_READ
	jne ssn_no_read
	mov eax,PAGE_READONLY
	mov [section_flags],eax
	jmp ssn_set_memory
ssn_no_read:
	mov eax,PAGE_NOACCESS
	mov [section_flags],eax

	;set section permissions
ssn_set_memory:
	mov edx,[section_header]
	mov eax,[edx+IMAGE_SECTION_HEADER.VirtualAddress]
	add eax,[image_base]
	mov ebx,[edx+IMAGE_SECTION_HEADER.VirtualSize]
	mov ecx,[APITable]
	lea edx,[vprotect_ret]
	stdcall dword [ecx+VirtualProtect],eax,ebx,[section_flags], edx
	test eax,eax
	jz ssn_exit_error

	;some output for the user
	mov edx,[section_header]
	mov eax,[edx+IMAGE_SECTION_HEADER.VirtualAddress]
	add eax,[image_base]
	writeRegisterToLog APITable, eax

ssn_exit_success:
	popad
	mov eax,1
	ret

ssn_exit_error:
	popad
	sub eax,eax
	ret
endp;

;check MZ und PE signature and return start of the image file header
proc verifyPE stdcall, image_base:DWORD, section_size:DWORD

local retval:DWORD

	pushad
	mov edx,[image_base]
	mov ax,[edx+IMAGE_DOS_HEADER.e_magic]
	cmp ax,IMAGE_DOS_SIGNATURE
	jne vpe_exit_error
	mov eax,[edx+IMAGE_DOS_HEADER.e_lfanew]
	add edx,eax
	mov eax,dword [edx]
	cmp eax,IMAGE_NT_SIGNATURE
	jne vpe_exit_error
	add edx,4
	mov [retval],edx

vpe_exit_success:
	popad
	mov eax,[retval]
	ret

vpe_exit_error:
	popad
	sub eax,eax
	ret

endp

;First 4 bytes of data seciton contain a checksum
;Verify that the checksum is correct
;TODO: CHECKSUM SIZE is atm hardcoded
proc verifyChecksum stdcall, section_address:DWORD, section_size:DWORD

	pushad
	mov ebx,dword [section_address]
	mov eax,[ebx]
	add ebx,4
	mov ecx,[section_size]
	sub ecx,4
	;checksum is in eax
	;pointer to file in ebx
	;size of file in ecx
	sub edi,edi
vs_calc_cs:
	sub edx,edx
	mov dl,byte [ebx]
	add edi,edx
	inc ebx
	dec ecx
	jnz vs_calc_cs
	;calculated checksum is in edi
	cmp edi,eax
	jne vs_exit_error

vs_exit_success:
	popad
	mov eax,1
	ret

vs_exit_error:
	popad
	sub eax,eax
	ret

endp