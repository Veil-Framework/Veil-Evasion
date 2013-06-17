#include "pe.h"
#include <iostream>
#include <string.h>
using namespace std;

namespace hyperion{

    /**
     * Checks whether file has a correct MZ and PE signature.
     * Returns the offset to the coff file header if signatures
     * are correct, otherwise a null pointer.
     */
    CoffHeader* getCoffHeader(FileInMemory* f){
        if(sizeof(MZHeader)>f->size){
            cerr << "Error: Not a valid executable, aborting" << endl;
            return 0;
        }

        //check MZ signature
        MZHeader* mz = (MZHeader*) f->adress;
        if(memcmp(mz->signature, MZ_SIGNATURE, MZ_SIGNATURE_SIZE != 0)){
            cerr << "Error: Not a valid MZ Signature, aborting" << endl;
            return 0;
        }
        cout << "Found valid MZ signature" << endl;

        //get PE header
        cout << "Found pointer to PE Header: 0x" << hex << mz->ptrPE << dec << endl;
        //ptrPe out of bounds?
        if(f->adress + mz->ptrPE >= f->adress + f->size){
            cout << "Error: pointer to PE in MZ header points to nowhere, aborting" << endl;
            return 0;
        }
        //no ptrPE?
        if (mz->ptrPE == 0){
            cout << "Error: pointer to PE in MZ header is a null pointer, aborting" << endl;
            return 0;
        }

        uint8_t* pe_sig = mz->ptrPE + (uint8_t*) f->adress;
        if(memcmp(pe_sig, PE_SIGNATURE, PE_SIGNATURE_SIZE) != 0){
            cout << "Error: no valid PE signature found, aborting" << endl;
            return 0;
        }
        cout << "Found valid PE signature" << endl;

        return (CoffHeader*) (f->adress + mz->ptrPE + PE_SIGNATURE_SIZE);
    }

    /**
     * Checks whether the file is a PE32 file and returns the corresponding header.
     * Returns a null pointer if the file is not a PE32 file
     */
    OptionalStandardHeader* getOptionalStandardHeader(CoffHeader* coff_ptr){
        OptionalStandardHeader* ret
            = (OptionalStandardHeader*) ((char*) coff_ptr + sizeof(CoffHeader));
        if (ret->Magic == OPTIONAL_HEADER_MAGIC_PE32) return ret;
        else return 0;
    }

    /**
     * Checks whether the file is a PE32+ file and returns the corresponding header.
     * Returns a null pointer if the file is not a PE32+ file
     */
    OptionalStandardPlusHeader* getOptionalStandardPlusHeader(CoffHeader* coff_ptr){
        OptionalStandardPlusHeader* ret
            = (OptionalStandardPlusHeader*) ((char*) coff_ptr + sizeof(CoffHeader));
        if (ret->Magic == OPTIONAL_HEADER_MAGIC_PE32PLUS) return ret;
        else return 0;
    }

    /**
     * Jumps from the OptionalStandardHeader to the OptionalWindowsHeader
     */
    OptionalWindowsHeader* getOptionalWindowsHeader(OptionalStandardHeader* os_ptr){
        return (OptionalWindowsHeader*) (((char*) os_ptr) + sizeof(OptionalStandardHeader));
    }

    /**
     * Jumps from the OptionalStandardPlusHeader to the OptionalWindowsPlusHeader
     */
    OptionalWindowsPlusHeader* getOptionalWindowsPlusHeader(OptionalStandardPlusHeader* os_ptr){
        return (OptionalWindowsPlusHeader*) (((char*) os_ptr) + sizeof(OptionalStandardPlusHeader));
    }

    /**
     * Jumps from the OptionalWindowsHeader to the first ImageDataDirectory
     */
    ImageDataDirectory* getFirstImageEntry(OptionalWindowsHeader* ow_ptr){
        return (ImageDataDirectory*) (((char*) ow_ptr) + sizeof(OptionalWindowsHeader));
    }

    /**
     * Jumps from the OptionalWindowsPlusHeader to the first ImageDataDirectory
     */
    ImageDataDirectory* getFirstImageEntry(OptionalWindowsPlusHeader* ow_plus_ptr){
        return (ImageDataDirectory*) (((char*) ow_plus_ptr) + sizeof(OptionalWindowsPlusHeader));
    }

    /**
     * Jumps from the first ImageDataDirectory to the first SectionHeader
     */
    SectionHeader* getFirstSectionHeader(ImageDataDirectory* id_ptr, uint32_t entries){
        return (SectionHeader*) (((char*) id_ptr) + entries*sizeof(ImageDataDirectory));
    }

    /**
     * Jumps from the first ImageDataDirectory to the first SectionHeader
     */
    SectionHeader* getNextSectionHeader(SectionHeader* section_ptr){
        return (SectionHeader*) (((char*) section_ptr) + sizeof(SectionHeader));
    }
}
