format PE GUI 4.0 DLL
entry DllEntryPoint

include '../Fasm/fasminclude/win32a.inc'
include 'aes/aes.inc'

section '.text' code readable executable

proc DllEntryPoint hinstDLL,fdwReason,lpvReserved
	mov	eax,TRUE
	ret
endp

; VOID ShowErrorMessage(HWND hWnd,DWORD dwError);
proc ShowErrorMessage hWnd,dwError
  local lpBuffer:DWORD
	lea	eax,[lpBuffer]
	invoke	FormatMessage,FORMAT_MESSAGE_ALLOCATE_BUFFER+FORMAT_MESSAGE_FROM_SYSTEM,0,[dwError],LANG_NEUTRAL,eax,0,0
	invoke	MessageBox,[hWnd],[lpBuffer],NULL,MB_ICONERROR+MB_OK
	invoke	LocalFree,[lpBuffer]
	ret
endp

; VOID ShowLastError(HWND hWnd);
proc ShowLastError hWnd
	invoke	GetLastError
	stdcall ShowErrorMessage,[hWnd],eax
	ret
endp

; VOID aesEncrypt(size, pointer to clear text, pointer to encryption, key)
; VOID aesDecrypt(size, pointer to encrypted text, pointer to decryption, key)
include 'aes/aes.asm'

section '.idata' import data readable writeable

  library kernel,'KERNEL32.DLL',\
	  user,'USER32.DLL'

  import kernel,\
	 GetLastError,'GetLastError',\
	 SetLastError,'SetLastError',\
	 FormatMessage,'FormatMessageA',\
	 LocalFree,'LocalFree'

  import user,\
	 MessageBox,'MessageBoxA'

section '.edata' export data readable

  export 'AES10.DLL',\
	 ShowErrorMessage,'ShowErrorMessage',\
	 ShowLastError,'ShowLastError',\
	 encAES,'aesEncrypt',\
	 decAES,'aesDecrypt'

section '.reloc' fixups data readable discardable

