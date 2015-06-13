; Hyperion 32-Bit container.exe

include 'imagebase.asm'
entry start

include '..\..\Fasm\fasminclude\win32a.inc'
include '..\..\FasmAES-1.0\aes\aes.inc'
include 'hyperion.inc'
include 'createstrings.inc'
include 'pe.inc'
include 'keysize.inc'

;data section which contains the encrypted exe
section '.bss' data readable writeable

	 decrypted_infile: include 'sizeofimage.asm'

;--------------------------------------------------

;data section which contains the encrypted exe
section '.data' data readable writeable

	 packed_infile: include 'infile.asm'

;--------------------------------------------------

section '.text' code readable executable

start:	 stdcall MainMethod
	 invoke ExitProcess,0

proc MainMethod stdcall
	 local str1[256]:BYTE,\
	 image_base:DWORD,\
	 data_section_header:DWORD,\
	 APITable:DWORD,\
	 CreateFileMapping_:DWORD,\
	 MapViewOfFile_:DWORD,\
	 UnmapViewOfFile_:DWORD,\
	 CreateFile_:DWORD,\
	 CloseHandle_:DWORD,\
	 DeleteFile_:DWORD,\
	 GetModuleHandle_:DWORD,\
	 VirtualAlloc_:DWORD,\
	 VirtualProtect_:DWORD,\
	 VirtualFree_:DWORD

	 ;pointer to the API table
	 lea eax,[CreateFileMapping_]
	 mov [APITable],eax

	 ;load APIs for log file access
	 stdcall loadLogAPIs,[APITable]
	 test eax,eax
	 jz main_exiterrornolog

	 ;create logfile and write init message into it
	 createStringLogTxt str1
	 mov eax,[APITable]
	 lea ebx,[str1]
	 stdcall dword [eax+DeleteFile],ebx
	 createStringStartingHyperionLines str1
	 lea eax,[str1]
	 stdcall writeLog,[APITable],eax
	 test eax,eax
	 jz main_exiterrornolog
	 createStringStartingHyperion str1
	 lea eax,[str1]
	 stdcall writeLog,[APITable],eax
	 test eax,eax
	 jz main_exiterrornolog
	 createStringStartingHyperionLines str1
	 lea eax,[str1]
	 stdcall writeLog,[APITable],eax
	 test eax,eax
	 jz main_exiterrornolog
	 stdcall writeNewLineToLog,[APITable]
	 test eax,eax
	 jz main_exiterrornolog

	 ;Load all necessary APIs
	 stdcall loadRegularAPIs, [APITable]
	 test eax,eax
	 jz main_exiterror
	 stdcall writeNewLineToLog,[APITable]
	 test eax,eax
	 jz main_exiterrornolog

	 ;Get image base
	 stdcall getImageBase, [APITable]
	 test eax,eax
	 jz main_exiterror
	 mov [image_base],eax

	 ;Get pointer to the data section of the crypter
	 stdcall getDataSection, [APITable], [image_base]
	 test eax,eax
	 jz main_exiterror
	 mov [data_section_header],eax

	 ;decrypt exe in data section
	 stdcall decryptExecutable, [APITable], [image_base], [data_section_header]
	 test eax,eax
	 jz main_exiterror

	 ;load the executable in the data section
	 stdcall loadExecutable, [APITable], [image_base], [data_section_header]
	 test eax,eax
	 jz main_exiterror

	 ;start program execution
	 mov edx,[image_base]
	 mov eax,[edx+IMAGE_DOS_HEADER.e_lfanew]
	 add eax,edx
	 add eax,4
	 ;image file header now in eax
	 add eax,sizeof.IMAGE_FILE_HEADER
	 mov eax,[eax+IMAGE_OPTIONAL_HEADER32.AddressOfEntryPoint]
	 add eax,[image_base]
	 ;entry point of original exe is now in eax
	 jmp eax

;finished without errors
main_exitsuccess:
	 stdcall writeNewLineToLog, [APITable]
	 createStringDone str1
	 lea eax,[str1]
	 stdcall writeLog,[APITable],eax
	 ret

;finished with errors after logfile API loading
main_exiterror:
	 stdcall writeNewLineToLog, [APITable]
	 createStringError str1
	 lea eax,[str1]
	 stdcall writeLog,[APITable],eax
	 ret

;finished with errors before logfile API loading
main_exiterrornolog:
	 ret

endp

;include necessary functions
include 'loadapis.asm'
include 'logfile.asm'
include 'getdatasection.asm'
include 'loadexecutable.asm'
include 'decryptexecutable.asm'
include '..\..\FasmAES-1.0\aes\aes.asm'

;import table
section '.idata' import data readable writeable

	 library kernel,'KERNEL32.DLL'

	 import kernel,\
	    GetProcAddress,'GetProcAddress',\
	    LoadLibrary,'LoadLibraryA',\
	    ExitProcess,'ExitProcess'
