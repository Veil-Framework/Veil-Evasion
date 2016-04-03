#ifndef ENCRYPTDATA_H_INCLUDED
#define ENCRYPTDATA_H_INCLUDED

#include "pe.h"
#include <vector>

using namespace std;

namespace hyperion{

    class PE32Analysis{
        public:
            vector<SectionHeader*> sections;
            uint32_t* image_base;
            uint32_t* file_alignment;
            uint32_t* section_alignment;
            uint32_t* size_of_image;
            bool error;

            PE32Analysis(FileInMemory* infile);
    };

}

#endif // ENCRYPTDATA_H_INCLUDED
