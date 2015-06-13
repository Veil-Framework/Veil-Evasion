;Dynamically load the needed APIs
;Strings are created on stack

;dllname: zero terminated string with dll name
;store: save the dll image base here
;Jumps to LoadLogAPIsExit if an Error Occurs
macro loadDLL dllname, store, exit
{
	lea eax,[dllname]
	invoke LoadLibrary,eax
	mov [retval],eax
	test eax,eax
	jz exit
	mov [store],eax
}

;functionname: zero terminated string with functions name
;dll_imagebase: imagebase of the dll
;returns: function pointer in eax
macro loadAPI functionname, dll_imagebase, exit
{
	lea eax,[functionname]
	invoke GetProcAddress,dword [dll_imagebase],eax
	mov [retval],eax
	test eax,eax
	jz exit
}

;write str1 and newline to logfile
;exit: function exit if an error occurs
macro writeStr1AndNewline exit
{
	lea eax,[str1]
	stdcall writeLog,[APITable],eax
	mov [retval],eax
	test eax,eax
	jz exit
	stdcall writeNewLineToLog, [APITable]
	mov [retval],eax
	test eax,eax
	jz exit
}

;Loads the basic functions for log file access
proc loadLogAPIs stdcall APITable:DWORD

local str1[256]:BYTE, kernel32_imagebase:DWORD, retval:DWORD

	pushad
	;Get Kernel32.Dll Imagebase
	createStringKernel32 str1
	loadDLL str1, kernel32_imagebase, LoadLogAPIsExit

	;Load CreateFileMapping API
	createStringCreateFileMapping str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+CreateFileMapping],eax

	;Load MapViewOfFile API
	createStringMapViewOfFile str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+MapViewOfFile],eax

	;Load UnmapViewOfFile API
	createStringUnmapViewOfFile str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+UnmapViewOfFile],eax

	;Load UnmapViewOfFile API
	createStringCreateFile str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+CreateFile],eax

	;Load CloseHandle API
	createStringCloseHandle str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+CloseHandle],eax

	;Load GetFileSize API
	createStringGetFileSize str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+GetFileSize],eax

	;Load DeleteFile API
	createStringDeleteFile str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+DeleteFile],eax

	;apis loaded successfully
	mov dword [retval],1

LoadLogAPIsExit:
	popad
	mov eax,[retval]
	ret

endp

;Loads all necessary APISs
proc loadRegularAPIs stdcall APITable:DWORD

local str1[256]:BYTE, kernel32_imagebase:DWORD, retval:DWORD

	pushad
	createStringLoading str1
	writeStr1AndNewline LoadRegularAPIsExit

	;Get Kernel32.Dll Imagebase
	createStringKernel32 str1
	writeStr1AndNewline LoadRegularAPIsExit
	loadDLL str1, kernel32_imagebase, LoadRegularAPIsExit

	;Load the APIs

	createStringGetModuleHandle str1
	writeStr1AndNewline LoadRegularAPIsExit
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+GetModuleHandle],eax

	createStringVirtualAlloc str1
	writeStr1AndNewline LoadRegularAPIsExit
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+VirtualAlloc],eax

	createStringVirtualProtect str1
	writeStr1AndNewline LoadRegularAPIsExit
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+VirtualProtect],eax

	createStringVirtualFree str1
	writeStr1AndNewline LoadRegularAPIsExit
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit
	mov edx,[APITable]
	mov [edx+VirtualFree],eax

	;Load more APIs here...
	mov [retval],1

LoadRegularAPIsExit:
	popad
	mov eax,[retval]
	ret
endp
