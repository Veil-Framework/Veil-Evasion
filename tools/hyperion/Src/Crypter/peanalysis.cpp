#include <iostream>
#include <string.h>
#include <windows.h>

#include "peanalysis.h"
#include "fileaccess.h"
#include "ostreamlog.h"

using namespace std;
using namespace hyperion;

extern OstreamLog ostreamlog;

namespace hyperion{

    /**
     * Analyses a PE32 file and collects all necessary data
     * (pointer to section header, pointer to image
     * base, ...) which are necessary for encryption and
     * exe loader.
     * Sets error to true if the analysis was not successful.
     */
    PE32Analysis::PE32Analysis(FileInMemory* infile){
        error=false;

        //get coff header and check whether its a valid exe
        CoffHeader* coff_header = getCoffHeader(infile);
        if (coff_header==0){
            error = true;
            return;
        }
        if (!(coff_header->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)){
            cerr << "Error: File is not an executable image, aborting..." << endl;
            error = true;
            return;
        }
        if (coff_header->Characteristics & IMAGE_FILE_DLL){
            cerr << "Error: File is a dll, aborting..." << endl;
            error = true;
            return;
        }

        //get optional header
        OptionalStandardHeader* os_ptr = getOptionalStandardHeader(coff_header);
        //is it 64-Bit?
        if(!os_ptr){
            cerr << "Error: File is PE64, aborting..." << endl;
            error = true;
            return;
        }

        //collect data from the different headers and get first section header of pe32
        ostreamlog << "Found a PE32 file" << endl;
        OptionalWindowsHeader* ow_ptr = getOptionalWindowsHeader(os_ptr);
        file_alignment = &ow_ptr->FileAlignment;
        section_alignment = &ow_ptr->SectionAlignment;
        size_of_image = &ow_ptr->SizeOfImage;
        image_base = &ow_ptr->ImageBase;
        ostreamlog << "Number of Data Directories: " << ow_ptr->NumberOfRvaAndSizes << endl;
        ostreamlog << "Image Base: 0x" << hex << *image_base << dec << endl;
        ImageDataDirectory* first_entry = getFirstImageEntry(ow_ptr);
        SectionHeader* section_header = getFirstSectionHeader(first_entry, ow_ptr->NumberOfRvaAndSizes);

        //iterate the section headers
        char name_zero[9];
        name_zero[8] = 0;
        memcpy(name_zero, section_header->Name, SECTION_NAME_SIZE);
        ostreamlog << endl << "Found Section: " << name_zero << endl;
        ostreamlog << "VSize: 0x" << hex << section_header->VirtualSize << ", VAddress: 0x" << section_header->VirtualAddress
        << ", RawSize: 0x" << section_header->SizeOfRawData << ", RawAddress: 0x" << section_header->PointerToRawData
        << dec << endl;
        sections.push_back(section_header);
        for(int i=1;i<coff_header->NumberOfSections;i++){
            section_header = getNextSectionHeader(section_header);
            memcpy(name_zero, section_header->Name, SECTION_NAME_SIZE);
            ostreamlog << endl << "Found Section: " << name_zero << endl;
            ostreamlog << "VSize: 0x" << hex << section_header->VirtualSize << ", VAddress: 0x" << section_header->VirtualAddress
            << ", RawSize: 0x" << section_header->SizeOfRawData << ", RawAddress: 0x" << section_header->PointerToRawData
            << dec << endl;
            sections.push_back(section_header);
        }
    }
}
