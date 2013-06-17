IMAGE_DOS_SIGNATURE = 05A4Dh
IMAGE_OS2_SIGNATURE = 0454Eh	   
IMAGE_OS2_SIGNATURE_LE = 0454Ch       
IMAGE_VXD_SIGNATURE = 0454Ch	
IMAGE_LX_SIGNATURE = 0584Ch    
IMAGE_NT_SIGNATURE = 04550h   

IMAGE_FILE_MACHINE_UNKNOWN	=	0 
IMAGE_FILE_MACHINE_I386 =	014ch 
IMAGE_FILE_MACHINE_R3000	=	0162h 
IMAGE_FILE_MACHINE_R4000	=	0166h 
IMAGE_FILE_MACHINE_R10000	=	0168h 
IMAGE_FILE_MACHINE_WCEMIPSV2	=	0169h 
IMAGE_FILE_MACHINE_ALPHA	=	0184h 
IMAGE_FILE_MACHINE_SH3	=	01a2h 
IMAGE_FILE_MACHINE_SH3DSP	=	01a3h 
IMAGE_FILE_MACHINE_SH3E =	01a4h 
IMAGE_FILE_MACHINE_SH4	=	01a6h 
IMAGE_FILE_MACHINE_SH5	=	01a8h 
IMAGE_FILE_MACHINE_ARM	=	01c0h 
IMAGE_FILE_MACHINE_THUMB	=	01c2h 
IMAGE_FILE_MACHINE_AM33 =	01d3h 
IMAGE_FILE_MACHINE_POWERPC	=	01F0h 
IMAGE_FILE_MACHINE_POWERPCFP	=	01f1h 
IMAGE_FILE_MACHINE_IA64 =	0200h 
IMAGE_FILE_MACHINE_MIPS16	=	0266h 
IMAGE_FILE_MACHINE_ALPHA64	=	0284h 
IMAGE_FILE_MACHINE_MIPSFPU	=	0366h 
IMAGE_FILE_MACHINE_MIPSFPU16	=	0466h 
IMAGE_FILE_MACHINE_AXP64	=	IMAGE_FILE_MACHINE_ALPHA64 
IMAGE_FILE_MACHINE_TRICORE	=	0520h 
IMAGE_FILE_MACHINE_CEF	=	0CEFh 
IMAGE_FILE_MACHINE_EBC	=	0EBCh 
IMAGE_FILE_MACHINE_AMD64	=	8664h 
IMAGE_FILE_MACHINE_M32R =	9041h 
IMAGE_FILE_MACHINE_CEE	=	0C0EEh 

IMAGE_SIZEOF_NT_OPTIONAL32_HEADER	=	224 
IMAGE_NT_OPTIONAL_HDR32_MAGIC	=	10bh 

IMAGE_FILE_RELOCS_STRIPPED = 0001h			 
IMAGE_FILE_EXECUTABLE_IMAGE = 0002h			 
IMAGE_FILE_LINE_NUMS_STRIPPED = 0004h		 
IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0008h		 
IMAGE_FILE_AGGRESIVE_WS_TRIM = 0010h		 
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0020h		 
IMAGE_FILE_BYTES_REVERSED_LO = 0080h		 
IMAGE_FILE_32BIT_MACHINE = 0100h			  
IMAGE_FILE_DEBUG_STRIPPED = 0200h			 
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0400h   
IMAGE_FILE_NET_RUN_FROM_SWAP = 0800h		 
IMAGE_FILE_SYSTEM = 1000h					 
IMAGE_FILE_DLL = 2000h						 
IMAGE_FILE_UP_SYSTEM_ONLY = 4000h   
IMAGE_FILE_BYTES_REVERSED_HI = 8000h   

IMAGE_SUBSYSTEM_UNKNOWN  = 0 
IMAGE_SUBSYSTEM_NATIVE	= 1 
IMAGE_SUBSYSTEM_WINDOWS_GUI  = 2 
IMAGE_SUBSYSTEM_WINDOWS_CUI  = 3 
IMAGE_SUBSYSTEM_OS2_CUI  = 5 
IMAGE_SUBSYSTEM_POSIX_CUI  = 7 
IMAGE_SUBSYSTEM_NATIVE_WINDOWS	= 8 
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI	= 9 
IMAGE_SUBSYSTEM_EFI_APPLICATION  = 10 
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11 
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER  = 12 
IMAGE_SUBSYSTEM_EFI_ROM  = 13 
IMAGE_SUBSYSTEM_XBOX  = 14 
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION  = 16 

IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE  = 0040h 
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY  = 0080h 
IMAGE_DLLCHARACTERISTICS_NX_COMPAT  = 0100h 
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION  = 0200h 
IMAGE_DLLCHARACTERISTICS_NO_SEH  = 0400h 
IMAGE_DLLCHARACTERISTICS_NO_BIND  = 0800h 
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER  = 2000h 
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE	= 8000h 

IMAGE_DIRECTORY_ENTRY_EXPORT  = 0 
IMAGE_DIRECTORY_ENTRY_IMPORT  = 1 
IMAGE_DIRECTORY_ENTRY_RESOURCE	= 2 
IMAGE_DIRECTORY_ENTRY_EXCEPTION  = 3 
IMAGE_DIRECTORY_ENTRY_SECURITY	= 4 
IMAGE_DIRECTORY_ENTRY_BASERELOC  = 5 
IMAGE_DIRECTORY_ENTRY_DEBUG  = 6 
IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7 
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE  = 7 
IMAGE_DIRECTORY_ENTRY_GLOBALPTR  = 8 
IMAGE_DIRECTORY_ENTRY_TLS  = 9 
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG  = 10 
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  = 11 
IMAGE_DIRECTORY_ENTRY_IAT  = 12 
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  = 13 
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 

IMAGE_SIZEOF_SECTION_HEADER	=	40 

IMAGE_SCN_TYPE_NO_PAD = 00000008h   
IMAGE_SCN_CNT_CODE = 00000020h	 
IMAGE_SCN_CNT_INITIALIZED_DATA = 00000040h   
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 00000080h   
IMAGE_SCN_LNK_OTHER = 00000100h   
IMAGE_SCN_LNK_INFO = 00000200h	 
IMAGE_SCN_LNK_REMOVE = 00000800h   
IMAGE_SCN_LNK_COMDAT = 00001000h   
IMAGE_SCN_NO_DEFER_SPEC_EXC = 00004000h   
IMAGE_SCN_GPREL = 00008000h   
IMAGE_SCN_MEM_FARDATA = 00008000h 
IMAGE_SCN_MEM_PURGEABLE = 00020000h 
IMAGE_SCN_MEM_16BIT = 00020000h 
IMAGE_SCN_MEM_LOCKED = 00040000h 
IMAGE_SCN_MEM_PRELOAD = 00080000h 
IMAGE_SCN_ALIGN_1BYTES = 00100000h   
IMAGE_SCN_ALIGN_2BYTES = 00200000h   
IMAGE_SCN_ALIGN_4BYTES = 00300000h   
IMAGE_SCN_ALIGN_8BYTES = 00400000h   
IMAGE_SCN_ALIGN_16BYTES = 00500000h   
IMAGE_SCN_ALIGN_32BYTES = 00600000h   
IMAGE_SCN_ALIGN_64BYTES = 00700000h   
IMAGE_SCN_ALIGN_128BYTES = 00800000h   
IMAGE_SCN_ALIGN_256BYTES = 00900000h   
IMAGE_SCN_ALIGN_512BYTES = 00A00000h   
IMAGE_SCN_ALIGN_1024BYTES = 00B00000h	
IMAGE_SCN_ALIGN_2048BYTES = 00C00000h	
IMAGE_SCN_ALIGN_4096BYTES = 00D00000h	
IMAGE_SCN_ALIGN_8192BYTES = 00E00000h	
IMAGE_SCN_LNK_NRELOC_OVFL = 01000000h	
IMAGE_SCN_MEM_DISCARDABLE = 02000000h	
IMAGE_SCN_MEM_NOT_CACHED = 04000000h   
IMAGE_SCN_MEM_NOT_PAGED = 08000000h   
IMAGE_SCN_MEM_SHARED = 10000000h   
IMAGE_SCN_MEM_EXECUTE = 20000000h   
IMAGE_SCN_MEM_READ = 40000000h	 
IMAGE_SCN_MEM_WRITE = 80000000h   
IMAGE_SCN_SCALE_INDEX = 00000001h     

struct IMAGE_DOS_HEADER 
	e_magic 	  dw	  ? 
	e_cblp		  dw	  ? 
	e_cp		  dw	  ? 
	e_crlc		  dw	  ? 
	e_cparhdr	  dw	  ? 
	e_minalloc	  dw	  ? 
	e_maxalloc	  dw	  ? 
	e_ss		  dw	  ? 
	e_sp		  dw	  ? 
	e_csum		  dw	  ? 
	e_ip		  dw	  ? 
	e_cs		  dw	  ? 
	e_lfarlc	  dw	  ? 
	e_ovno		  dw	  ? 
	e_res		  rw	  4 
	e_oemid 	  dw	  ? 
	e_oeminfo	  dw	  ? 
	e_res2		  rw	  10 
	e_lfanew	  dd	  ? 
ends 

struct IMAGE_FILE_HEADER  
	Machine 	      dw    ? 
	NumberOfSections      dw    ? 
	TimeDateStamp	      dd    ? 
	PointerToSymbolTable  dd    ? 
	NumberOfSymbols       dd    ? 
	SizeOfOptionalHeader  dw    ? 
	Characteristics       dw    ? 
ends 

struct IMAGE_DATA_DIRECTORY  
	VirtualAddress	  dd	  ? 
	isize		  dd	  ? 
ends 

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16 

struct IMAGE_OPTIONAL_HEADER32 
	Magic			      dw       ? 
	MajorLinkerVersion	      db       ? 
	MinorLinkerVersion	      db       ? 
	SizeOfCode		      dd       ? 
	SizeOfInitializedData	      dd       ? 
	SizeOfUninitializedData       dd       ? 
	AddressOfEntryPoint	      dd       ? 
	BaseOfCode		      dd       ? 
	BaseOfData		      dd       ? 
	ImageBase		      dd       ? 
	SectionAlignment	      dd       ? 
	FileAlignment		      dd       ? 
	MajorOperatingSystemVersion   dw       ? 
	MinorOperatingSystemVersion   dw       ? 
	MajorImageVersion	      dw       ? 
	MinorImageVersion	      dw       ? 
	MajorSubsystemVersion	      dw       ? 
	MinorSubsystemVersion	      dw       ? 
	Win32VersionValue	      dd       ? 
	SizeOfImage		      dd       ? 
	SizeOfHeaders		      dd       ? 
	CheckSum		      dd       ? 
	Subsystem		      dw       ? 
	DllCharacteristics	      dw       ? 
	SizeOfStackReserve	      dd       ? 
	SizeOfStackCommit	      dd       ? 
	SizeOfHeapReserve	      dd       ? 
	SizeOfHeapCommit	      dd       ? 
	LoaderFlags		      dd       ? 
	NumberOfRvaAndSizes	      dd       ? 
	DataDirectory				  rb (sizeof.IMAGE_DATA_DIRECTORY*IMAGE_NUMBEROF_DIRECTORY_ENTRIES) 
ends 

struct IMAGE_NT_HEADERS32 
	Signature	  dd			   ? 
	FileHeader	  IMAGE_FILE_HEADER	   ?	 
	OptionalHeader	  IMAGE_OPTIONAL_HEADER32  ? 
ends 

IMAGE_SIZEOF_SHORT_NAME = 8 

struct IMAGE_SECTION_HEADER  
  _Name db IMAGE_SIZEOF_SHORT_NAME dup (?)  
  union  
    PhysicalAddress	dd ?  
    VirtualSize 	dd ?  
  ends	
  VirtualAddress	dd ?  
  SizeOfRawData 	dd ?  
  PointerToRawData	dd ?  
  PointerToRelocations	dd ?  
  PointerToLinenumbers	dd ?  
  NumberOfRelocations	dw ?  
  NumberOfLinenumbers	dw ?  
  Characteristics	dd ?  
ends 

struct IMAGE_EXPORT_DIRECTORY 
	Characteristics dd	? 
	TimeDateStamp	dd	? 
	MajorVersion	dw	? 
	MinorVersion	dw	? 
	Name_	dd	? 
	Base	dd	? 
	NumberOfFunctions	dd	? 
	NumberOfNames	dd	? 
	AddressOfFunctions	dd	? 
	AddressOfNames	dd	? 
	AddressOfNameOrdinals	dd	? 
ends 

struct IMAGE_IMPORT_DESCRIPTOR 
	union 
	Characteristics dd	? 
	OriginalFirstThunk	dd	? 
	ends 
	TimeDateStamp	dd	? 
	ForwarderChain	dd	? 
	Name_	dd	? 
	FirstThunk	dd	? 
ends 

struct IMAGE_THUNK_DATA32 
	union 
	ForwarderString dd	? 
	Function	dd	? 
	Ordinal dd	? 
	AddressOfData	dd	? 
	ends 
ends 

struct IMAGE_IMPORT_BY_NAME 
	Hint	dw	? 
	Name_	rb  1 
ends 

IMAGE_ORDINAL_FLAG32 = 80000000h 

struct IMAGE_BOUND_IMPORT_DESCRIPTOR 
	TimeDateStamp	dd	? 
	OffsetModuleName	dw	? 
	NumberOfModuleForwarderRefs	dw	? 
ends 

struct IMAGE_BOUND_FORWARDER_REF 
	TimeDateStamp	dd	? 
	OffsetModuleName	dw	? 
	Reserved	dw	? 
ends 

struct IMAGE_RESOURCE_DIRECTORY 
	Characteristics dd	? 
	TimeDateStamp	dd	? 
	MajorVersion	dw	? 
	MinorVersion	dw	? 
	NumberOfNamedEntries	dw	? 
	NumberOfIdEntries	dw	? 
ends 

struct IMAGE_RESOURCE_DIRECTORY_ENTRY 
	_id	dd ?	 
	_offset dd ? 
ends 

struct IMAGE_RESOURCE_DIRECTORY_STRING 
	Length_     dw	? 
	NameString	rb  1 
ends 

struct IMAGE_RESOURCE_DATA_ENTRY 
	OffsetToData	dd	? 
	Size_	dd	? 
	CodePage	dd	? 
	Reserved	dd	? 
ends 

RT_NEWRESOURCE			     = 00002000h 
RT_ERROR			     = 00007fffh 
RT_CURSOR			     = 000000001 
RT_BITMAP			     = 000000002 
RT_ICON 			     = 000000003 
RT_MENU 			     = 000000004 
RT_DIALOG			     = 000000005 
RT_STRING			     = 000000006 
RT_FONTDIR			     = 000000007 
RT_FONT 			     = 000000008 
RT_ACCELERATORS 		     = 000000009 
RT_RCDATA			     = 0000000010 
RT_MESSAGETABLE 		     = 0000000011 
RT_GROUP_CURSOR 		     = 0000000012 
RT_GROUP_ICON			     = 0000000014 
RT_VERSION			     = 0000000016 
RT_NEWBITMAP			     = (RT_BITMAP or RT_NEWRESOURCE) 
RT_NEWMENU			     = (RT_MENU   or RT_NEWRESOURCE) 
RT_NEWDIALOG			     = (RT_DIALOG or RT_NEWRESOURCE) 

struct IMAGE_BASE_RELOCATION 
	VirtualAddress	dd	? 
	SizeOfBlock	    dd	? 
ends 

IMAGE_REL_BASED_ABSOLUTE  = 0 
IMAGE_REL_BASED_HIGH  = 1 
IMAGE_REL_BASED_LOW  = 2 
IMAGE_REL_BASED_HIGHLOW  = 3 
IMAGE_REL_BASED_HIGHADJ  = 4 
IMAGE_REL_BASED_MIPS_JMPADDR  = 5 
IMAGE_REL_BASED_SECTION  = 6 
IMAGE_REL_BASED_REL32  = 7 

struct IMAGE_TLS_DIRECTORY32 
	StartAddressOfRawData	dd	? 
	EndAddressOfRawData	dd	? 
	AddressOfIndex	dd	? 
	AddressOfCallBacks	dd	? 
	SizeOfZeroFill	dd	? 
	Characteristics dd	? 
ends 

struct IMAGE_LOAD_CONFIG_DIRECTORY32 
	Characteristics dd	? 
	TimeDateStamp	dd	? 
	MajorVersion	dw	? 
	MinorVersion	dw	? 
	GlobalFlagsClear	dd	? 
	GlobalFlagsSet	dd	? 
	CriticalSectionDefaultTimeout	dd	? 
	DeCommitFreeBlockThreshold	dd	? 
	DeCommitTotalFreeThreshold	dd	? 
	LockPrefixTable dd	? 
	MaximumAllocationSize	dd	? 
	VirtualMemoryThreshold	dd	? 
	ProcessHeapFlags	dd	? 
	ProcessAffinityMask	dd	? 
	CSDVersion	dw	? 
	Reserved1	dw	? 
	EditList	dd	? 
	Reserved	rd  1 
ends