;Dynamically load the needed APIs
;Strings are created on stack

;dllname: zero terminated string with dll name
;store: save the dll image base here
;Jumps to LoadLogAPIsExit if an Error Occurs
macro loadDLL dllname, store, exit
{
	lea eax,[dllname]
	invoke LoadLibrary,eax
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
	test eax,eax
	jz exit
}

;Loads all necessary APISs
proc loadRegularAPIs stdcall APITable:DWORD

local str1[256]:BYTE, kernel32_imagebase:DWORD

	pushad
	writeWithNewLine createStringLoading, str1, LoadRegularAPIsExit_Error

	;Get Kernel32.Dll Imagebase
	writeWithNewLine createStringKernel32, str1, LoadRegularAPIsExit_Error
	loadDLL str1, kernel32_imagebase, LoadRegularAPIsExit_Error

	;Load GetModuleHandle
	writeWithNewLine createStringGetModuleHandle, str1, LoadRegularAPIsExit_Error
	loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit_Error
	mov edx,[APITable]
	mov [edx+GetModuleHandle],eax

	;Load VirtualAlloc
	writeWithNewLine createStringVirtualAlloc, str1, LoadRegularAPIsExit_Error
	loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit_Error
	mov edx,[APITable]
	mov [edx+VirtualAlloc],eax

	;Load VirtualProtect
	writeWithNewLine createStringVirtualProtect, str1, LoadRegularAPIsExit_Error
	loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit_Error
	mov edx,[APITable]
	mov [edx+VirtualProtect],eax

	;Load VirtualFree
	writeWithNewLine createStringVirtualFree, str1, LoadRegularAPIsExit_Error
	loadAPI str1, kernel32_imagebase, LoadRegularAPIsExit_Error
	mov edx,[APITable]
	mov [edx+VirtualFree],eax

	popad
	mov eax,1
	ret
	
LoadRegularAPIsExit_Error:
	popad
	mov eax,0
	ret
endp

;Loads the basic functions for log file access
proc loadLogAPIs stdcall APITable:DWORD

local str1[256]:BYTE, kernel32_imagebase:DWORD

	pushad
	;Get Kernel32.Dll Imagebase
	createStringKernel32 str1
	loadDLL str1, kernel32_imagebase, LoadLogAPIsExit_Error

	;Load CreateFileMapping API
	createStringCreateFileMapping str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
	mov edx,[APITable]
	mov [edx+CreateFileMapping],eax

	;Load MapViewOfFile API
	createStringMapViewOfFile str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
	mov edx,[APITable]
	mov [edx+MapViewOfFile],eax

	;Load UnmapViewOfFile API
	createStringUnmapViewOfFile str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
	mov edx,[APITable]
	mov [edx+UnmapViewOfFile],eax

	;Load UnmapViewOfFile API
	createStringCreateFile str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
	mov edx,[APITable]
	mov [edx+CreateFile],eax

	;Load CloseHandle API
	createStringCloseHandle str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
	mov edx,[APITable]
	mov [edx+CloseHandle],eax

	;Load GetFileSize API
	createStringGetFileSize str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
	mov edx,[APITable]
	mov [edx+GetFileSize],eax

	;Load DeleteFile API
	createStringDeleteFile str1
	loadAPI str1, kernel32_imagebase, LoadLogAPIsExit_Error
	mov edx,[APITable]
	mov [edx+DeleteFile],eax

	;apis loaded successfully
	popad
	mov eax,1
	ret

LoadLogAPIsExit_Error:
	popad
	mov eax,0
	ret

endp
