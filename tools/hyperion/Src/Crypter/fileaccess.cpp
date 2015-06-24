#include <iostream>
#include <fstream>

#include "fileaccess.h"
#include "ostreamlog.h"

using namespace std;
using namespace hyperion;

extern OstreamLog ostreamlog;

namespace hyperion{

    /**
    * Opens a file and copies it into memory and returns
    */
    FileInMemory::FileInMemory(const char* file_name){
        //open input file
        ostreamlog << "Opening " << file_name << endl;
        ifstream file_stream;
        file_stream.open (file_name, ios::in | ios::binary | ios::ate);
        if(!file_stream.is_open()){
            cerr << "Error: Could not open " << file_name <<endl;
            open=false;
            return;
        }

        //copy into memory
        unsigned long file_size = file_stream.tellg();
        file_stream.seekg(0);
        char* file = new char[file_size];
        if(!file){
            cerr << "Error: Could not allocate memory, aborting" << endl;
            open=false;
            return;
        }
        file_stream.read(file, file_size);
        file_stream.close();
        ostreamlog << "Copied file to memory location: 0x" << hex << (unsigned int) file << dec << endl;

        //file opened successfully
        adress = file;
        size = file_size;
        open=true;
        return;
    }

    /**
     * Deletes a File instance and deallocates
     * the corresponding memory
     */
     FileInMemory::~FileInMemory(){
        if (adress!=0) delete adress;
     }
}
