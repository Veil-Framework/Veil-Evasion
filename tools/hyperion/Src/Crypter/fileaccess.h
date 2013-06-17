#ifndef FILEACCESS_H_INCLUDED
#define FILEACCESS_H_INCLUDED

#include "stdint.h"

namespace hyperion{

    class FileInMemory{
        public:
            char* adress;
            unsigned long size;
            bool open;

            FileInMemory(const char* file_name);
            ~FileInMemory();
    };

}

#endif // FILEACCESS_H_INCLUDED
