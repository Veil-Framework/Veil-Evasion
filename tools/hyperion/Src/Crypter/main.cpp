#include <iostream>
#include <string.h>
#include <string>
#include <windows.h>

#include "pe.h"
#include "fileaccess.h"
#include "peanalysis.h"
#include "createoutput.h"

using namespace std;
using namespace hyperion;

int main(int argc, char *argv[])
{
    if(argc<3){
        cout<<"PECrypter 1.0 by Christian Ammann"<<endl;
        cout<<"Usage: crypter.exe <infile> <outfile>"<<endl;
        return 0;
    }
    //input file examples
    const char* infile_name = argv[1];

    //32-bit container asm source
    const char* container_main_name = "Src\\FasmContainer32\\main.asm";
    const char* container_infile_name = "Src\\FasmContainer32\\infile.asm";
    const char* container_imagebase_name = "Src\\FasmContainer32\\imagebase.asm";
    const char* container_imagesize_name = "Src\\FasmContainer32\\sizeofimage.asm";
    const char* container_keysize_name = "Src\\FasmContainer32\\keysize.inc";

    //output file of fasm
    const char* output_name = argv[2];
    //path to fasm.exe
    const char* fasm_exe = "Fasm\\FASM.EXE";

    //open input file
	cout<<endl;
    FileInMemory* infile = new FileInMemory(infile_name);
    if(!infile->open) return 0;

    //collect data from the input file pe header
    PE32Analysis* infile_analysis = new PE32Analysis(infile);
    if(infile_analysis->error){
        delete infile_analysis;
        delete infile;
        return 0;
    }
    cout << endl;

    //create infile fasm array and write it to container_infile_asm
    if(!createInfileArray(infile, container_infile_name)){
        delete infile_analysis;
        delete infile;
        return 0;
    }

    //create image base asm representation and write it to container_imagebase_name
    if(!createImageBase(infile_analysis, container_imagebase_name)){
        delete infile_analysis;
        delete infile;
        return 0;
    }

    //create image size asm representation and write it to container_imagebase_name
    if(!createImageSize(infile_analysis, container_imagesize_name)){
        delete infile_analysis;
        delete infile;
        return 0;
    }

    //create an keysize equate for fasm sources
    if(!createKeySize(container_keysize_name)){
        delete infile_analysis;
        delete infile;
        return 0;
    }

    //get current directory
    char* current_directory = new char[3000];
    if(!GetCurrentDirectory(3000, current_directory)){
        cout<<"Error: Could not receive current directory";
        delete infile_analysis;
        delete infile;
        return 0;
    }

    //start fasm to generate a packed executable
    string cmd_line = "";
    cmd_line+=fasm_exe;
    cmd_line+=" ";
    cmd_line+=container_main_name;
    cmd_line+=" ";
    cmd_line+=output_name;
    char* cmd_line_noconst = new char[cmd_line.size()+1];
    strcpy(cmd_line_noconst, cmd_line.c_str());
    STARTUPINFO startup_info;
    ZeroMemory( &startup_info, sizeof(startup_info) );
    startup_info.cb = sizeof(startup_info);
    PROCESS_INFORMATION process_info;
    cout<<"Starting FASM with the following parameters:"<<endl;
    cout<<"Commandline: "<<cmd_line_noconst<<endl;
    cout<<"FASM Working Directory: "<<current_directory<<endl<<endl;
    if(CreateProcess(fasm_exe, cmd_line_noconst, 0, 0, false, 0, 0, current_directory, &startup_info, &process_info))
        cout<<"Executing fasm.exe"<<endl;
    else{
        cout<<"Error: Could not start fasm.exe"<<endl;
        cout<<"Error Code: "<<GetLastError();
    }

    //close application
    cout << endl;
    delete []cmd_line_noconst;
    delete []current_directory;
    delete infile_analysis;
    delete infile;
    return 0;
}
