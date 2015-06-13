;write <content> into log.txt
;returns false if an eerror occurs
proc writeLog stdcall APITable:DWORD, content:DWORD

local str1[256]:BYTE, oldlogsize:DWORD, newlogsize:DWORD, contentsize:DWORD,\
      filehandle:DWORD, filemappingobject:DWORD, mapaddress:DWORD, retval:DWORD

	 pushad
	 ;open file
	 createStringLogTxt str1
	 mov eax,[APITable]
	 lea ebx,[str1]
	 sub edx,edx
	 stdcall dword [eax+CreateFile], ebx, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, edx, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, edx
	 mov [retval],eax
	 test eax,eax
	 jz wl_logexit
	 mov [filehandle],eax

	 ;get logfile size
	 mov eax,[APITable]
	 stdcall dword [eax+GetFileSize], dword [filehandle], 0
	 mov [oldlogsize],eax

	 ;get size of string for logfile for concatenation
	 stdcall strlen, dword [content]
	 mov [contentsize], eax
	 add eax,dword [oldlogsize]
	 mov [newlogsize], eax

	 ;create the file mapping
	 sub ebx,ebx
	 mov edx,[APITable]
	 stdcall dword [edx+CreateFileMapping], dword [filehandle], ebx, PAGE_READWRITE, ebx, eax, ebx
	 mov [retval],eax
	 test eax, eax
	 jz wl_closelogfile
	 mov [filemappingobject],eax

	 sub ebx,ebx
	 mov edx,[APITable]
	 stdcall dword [edx+MapViewOfFile], eax, FILE_MAP_ALL_ACCESS, ebx, ebx, dword [newlogsize]
	 mov [retval],eax
	 test eax, eax
	 jz wl_closemaphandle
	 mov [mapaddress],eax

	 ;copy string into map
	 add eax,[oldlogsize]
	 mov edi,eax
	 mov esi,[content]
	 mov ecx,[contentsize]
	 repz movsb
	 mov [retval],1

wl_unmapfile:
	 mov edx,[APITable]
	 stdcall dword [edx+UnmapViewOfFile], dword [mapaddress]

wl_closemaphandle:
	 mov edx,[APITable]
	 stdcall dword [edx+CloseHandle], dword [filemappingobject]

wl_closelogfile:
	 mov eax,[APITable]
	 stdcall dword [eax+CloseHandle], dword [filehandle]

wl_logexit:
	 popad
	 mov eax,[retval]
	 ret;

endp

;adds a <newline> to the logfile
;returns false if an error occurs
proc writeNewLineToLog APITable:DWORD

local str1[3]:BYTE

	 lea eax,[str1]
	 mov byte [eax+0],13
	 mov byte [eax+1],10
	 mov byte [eax+2],0
	 stdcall writeLog, [APITable], eax
	 ret

endp

;adds a <space> to the logfile
;returns false if an eerror occurs
proc writeSpaceToLog APITable:DWORD

local str1[2]:BYTE

	 lea eax,[str1]
	 mov byte [eax+0],' '
	 mov byte [eax+1],0
	 stdcall writeLog, [APITable], eax
	 ret

endp

;adds "<hexadecimal value>" to the logfile
;returns false if an error occurs
proc writeRegisterToLog stdcall APITable:DWORD, Value:DWORD

local str1[10]:BYTE, retval:DWORD

	 pushad
	 lea eax,[str1]
	 stdcall binToString, eax, [Value]
	 stdcall writeLog,[APITable],eax
	 mov [retval],eax
	 test eax,eax
	 jz wrtl_exit
	 stdcall writeNewLineToLog,[APITable]
	 mov [retval],eax
	 test eax,eax
	 jz wrtl_exit

wrtl_exit:
	 popad
	 mov eax,[retval]
	 ret

endp

;converts <bin> into an 8 byte string and stores it <buffer>
proc binToString stdcall buffer:DWORD, bin:DWORD

	 pushad
	 mov ebx,[bin]
	 mov ecx,8

bts_next_byte:
	 mov eax,ebx
	 and eax,0000000fh
	 cmp eax,9
	 jg bts_add_55
bts_add_48:
	 add eax,48
	 jmp bts_store_bin
bts_add_55:
	 add eax,55
bts_store_bin:
	 dec ecx
	 mov edx,[buffer]
	 mov byte [ecx+edx],al
	 test ecx,ecx
	 jz bts_finished_conversion
	 shr ebx,4
	 jmp bts_next_byte

bts_finished_conversion:
	 mov eax,[buffer]
	 mov byte [eax+8],0
	 popad
	 ret
endp

;get the length of a string
proc strlen stdcall string_ptr:DWORD

	 push edi
	 push ecx
	 mov edi,[string_ptr]
	 sub ecx, ecx
	 sub al, al
	 not ecx
	 cld
	 repne scasb
	 not ecx
	 dec ecx
	 mov eax,ecx
	 pop ecx
	 pop edi
	 ret

endp

;writes a string and a newline to the logfile
macro writeWithNewLine char_sequence, char_buffer, error_exit
{
	char_sequence char_buffer
	lea eax,[str1]
	stdcall writeLog,[APITable],eax
	test eax,eax
	jz error_exit
	stdcall writeNewLineToLog,[APITable]
	test eax,eax
	jz error_exit
}