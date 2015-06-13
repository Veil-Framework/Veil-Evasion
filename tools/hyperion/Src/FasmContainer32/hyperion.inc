CreateFileMapping	equ 0
MapViewOfFile		equ CreateFileMapping + 4
UnmapViewOfFile 	equ MapViewOfFile     + 4
CreateFile		equ UnmapViewOfFile   + 4
CloseHandle		equ CreateFile	      + 4
GetFileSize		equ CloseHandle       + 4
DeleteFile		equ GetFileSize       + 4
GetModuleHandle 	equ DeleteFile	      + 4
VirtualAlloc		equ GetModuleHandle   + 4
VirtualProtect		equ VirtualAlloc      + 4
VirtualFree		equ VirtualProtect    + 4

SIZE_DATA_SECTION_NAME	equ 5
SIZE_CHECKSUM		equ 4