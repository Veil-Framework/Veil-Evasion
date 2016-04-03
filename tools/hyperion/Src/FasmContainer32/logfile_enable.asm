;-------------------------------------------
;the content of this file is excluded,      |
;when the user disables logging features    |
;in hyperion command line. pls keep in mind |
;and dont rely on its existence.            |
;-------------------------------------------  

;--- Begin Macro Section ---

;writes a string and a newline to the logfile
macro writeWithNewLine char_sequence, char_buffer, error_exit
{
	char_sequence char_buffer
	lea eax,[str1]
	stdcall writeLog_,[APITable],eax
	test eax,eax
	jz error_exit
	stdcall writeNewLineToLog_,[APITable]
	test eax,eax
	jz error_exit
}

;write a string to the logfile
macro writeLog apitable, content{
	stdcall writeLog_,[apitable], content
}

;delete old log file and create a new one
macro initLogFile apitable{
	 stdcall initLogFile_, [apitable]
}

;write a newline into logfile
macro writeNewLineToLog apitable{
	stdcall writeNewLineToLog_, [apitable]
}

;write a register value into logile
macro writeRegisterToLog apitable, value{
	stdcall writeRegisterToLog_, [apitable], value
}

;--- End Macro Section ---

;write <content> into log.txt
;returns false if an eerror occurs
proc writeLog_ stdcall APITable:DWORD, content:DWORD

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
	 stdcall strlen_, dword [content]
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
proc writeNewLineToLog_ APITable:DWORD

local str1[3]:BYTE

	 lea eax,[str1]
	 mov byte [eax+0],13
	 mov byte [eax+1],10
	 mov byte [eax+2],0
	 stdcall writeLog_, [APITable], eax
	 ret

endp

;adds "<hexadecimal value>" to the logfile
;returns false if an error occurs
proc writeRegisterToLog_ stdcall APITable:DWORD, Value:DWORD

local str1[10]:BYTE, retval:DWORD

	 pushad
	 lea eax,[str1]
	 stdcall binToString_, eax, [Value]
	 stdcall writeLog_,[APITable],eax
	 mov [retval],eax
	 test eax,eax
	 jz wrtl_exit
	 stdcall writeNewLineToLog_,[APITable]
	 mov [retval],eax
	 test eax,eax
	 jz wrtl_exit

wrtl_exit:
	 popad
	 mov eax,[retval]
	 ret

endp

;converts <bin> into an 8 byte string and stores it <buffer>
proc binToString_ stdcall buffer:DWORD, bin:DWORD

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
proc strlen_ stdcall string_ptr:DWORD

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

;Write initial message into logfile
proc initLogFile_ stdcall APITable:DWORD

local str1[256]:BYTE

	pushad
	createStringLogTxt str1
	mov eax,[APITable]
	lea ebx,[str1]
	stdcall dword [eax+DeleteFile],ebx
	createStringStartingHyperionLines str1
	lea eax,[str1]
	stdcall writeLog_,[APITable],eax
	test eax,eax
	jz ilf_exit_error
	createStringStartingHyperion str1
	lea eax,[str1]
	stdcall writeLog_,[APITable],eax
	test eax,eax
	jz ilf_exit_error
	createStringStartingHyperionLines str1
	lea eax,[str1]
	stdcall writeLog_,[APITable],eax
	test eax,eax
	jz ilf_exit_error
	stdcall writeNewLineToLog_,[APITable]
	test eax,eax
	jz ilf_exit_error

ilf_exit_success:
	popad
	mov eax,1
	ret

ilf_exit_error:
	popad
	sub eax,eax
	ret

endp