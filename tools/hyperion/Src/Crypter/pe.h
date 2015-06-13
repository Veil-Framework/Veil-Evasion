#ifndef PE_H_INCLUDED
#define PE_H_INCLUDED

#include "fileaccess.h"
#include "stdint.h"

#define MZ_SIGNATURE "MZ"
#define MZ_SIGNATURE_SIZE 2
#define PE_SIGNATURE "PE\0\0"
#define PE_SIGNATURE_SIZE 4
#define OPTIONAL_HEADER_MAGIC_PE32 0x10b
#define OPTIONAL_HEADER_MAGIC_PE32PLUS 0x20b
#define SECTION_NAME_SIZE 8
#define IMAGE_BASE_ALIGNMENT 0x10000

namespace hyperion{

    struct MZHeader{
        uint8_t signature[MZ_SIGNATURE_SIZE];
        uint8_t data[0x3a];
        uint32_t ptrPE;
    };

    struct CoffHeader{
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    };

    struct OptionalStandardHeader{
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint32_t BaseOfData;
    };

    struct OptionalStandardPlusHeader{
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
    };

    struct OptionalWindowsHeader{
        uint32_t ImageBase; //plus
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint32_t SizeOfStackReserve; //plus
        uint32_t SizeOfStackCommit; //plus
        uint32_t SizeOfHeapReserve; //plus
        uint32_t SizeOfHeapCommit; //plus
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
    };

    struct OptionalWindowsPlusHeader{
        uint64_t ImageBase; //plus
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint64_t SizeOfStackReserve; //plus
        uint64_t SizeOfStackCommit; //plus
        uint64_t SizeOfHeapReserve; //plus
        uint64_t SizeOfHeapCommit; //plus
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
    };

    struct ImageDataDirectory {
        uint32_t VirtualAddress;
        uint32_t Size;
    };

    struct SectionHeader{
        uint8_t Name[SECTION_NAME_SIZE];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    };

    CoffHeader* getCoffHeader(FileInMemory* f);

    OptionalStandardHeader* getOptionalStandardHeader(CoffHeader* coff_ptr);
    OptionalStandardPlusHeader* getOptionalStandardPlusHeader(CoffHeader* coff_ptr);

    OptionalWindowsHeader* getOptionalWindowsHeader(OptionalStandardHeader* os_ptr);
    OptionalWindowsPlusHeader* getOptionalWindowsPlusHeader(OptionalStandardPlusHeader* os_ptr);

    ImageDataDirectory* getFirstImageEntry(OptionalWindowsHeader* ow_ptr);
    ImageDataDirectory* getFirstImageEntry(OptionalWindowsPlusHeader* ow_plus_ptr);

    SectionHeader* getFirstSectionHeader(ImageDataDirectory* id_ptr, uint32_t entries);
    SectionHeader* getNextSectionHeader(SectionHeader* section_ptr);
}

#endif // PE_H_INCLUDED
