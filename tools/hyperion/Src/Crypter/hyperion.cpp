#include <iostream>
#include <string.h>
#include <string>
#include <windows.h>

#include "hyperion.h"

using namespace std;
using namespace hyperion;

//global logging framework variable
OstreamLog ostreamlog = 0;

int main(int argc, char *argv[])
{
    if(argc<3){
        cout << "Hyperion PE-Crypter" << endl;
        cout << "Version 1.1 by Christian Ammann" << endl;
        cout << "Http://www.nullsecurity.net" << endl;
        cout << endl;
        cout << "Usage: hyperion.exe <options> <infile> <outfile>" << endl;
        cout << "List of available options:" << endl;
        cout << "  -k <size> \t Length of random AES key in bytes." << endl;
        cout << "            \t Default value is 6." << endl;
        cout << "  -s <size> \t Each byte of the key has a range between" << endl;
        cout << "            \t 0 and <size-1>. Default value is 4." << endl;
        cout << "  -l, --logile \t The packed executable generates a log.txt" << endl;
        cout << "          \t on startup for debugging purpose" << endl;
        cout << "  -v, --verbose\t Print verbose informations while running." << endl;
        return 0;
    }

    //command line options
    unsigned int key_length = 6;
    unsigned int key_space = 4;
    bool create_log = false;
    bool display_verbose = false;
    char* infile_name = 0;
    char* output_name = 0;

    //parse commandline parameters
    for(int i=1; i<argc; i++){
        if(i==argc-2){
            infile_name = argv[i];
        }
        else if(i==argc-1){
            output_name = argv[i];
        }
        else if(!strcmp(argv[i], "-k")){
            i++;
            key_length = (unsigned int) strtol(argv[i], NULL, 10);
        }
        else if(!strcmp(argv[i], "-s")){
            i++;
            key_space = (unsigned int) strtol(argv[i], NULL, 10);
        }
        else if(!strcmp(argv[i], "-l") || !strcmp(argv[i], "--logfile")){
            create_log = true;
        }
        else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")){
            display_verbose = true;
        }
        else{
            cerr << "Error: Invalid parameter" << endl;
            return -1;
        }
    }

    //init logging framework
    ostreamlog = OstreamLog(display_verbose);

    //check whether specified parameters are valid
    if(key_length > 16 || key_length<1){
        cerr << "Key length has to be a value between 1 and 16" << endl;
        return -1;
    }
    if(key_space > 255 || key_space<2){
        cerr << "Key space has to be a value between 2 and 255" << endl;
        return -1;
    }

    ostreamlog <<endl;
    ostreamlog << " -------------------------------" << endl;
    ostreamlog << "| Stage 1: Analyzing input file |" << endl;
    ostreamlog << " -------------------------------" << endl;
    ostreamlog <<endl;
    //open input file
    FileInMemory* infile = new FileInMemory(infile_name);
    if(!infile->open){
        return -1;
    }
    //collect data from the input file's pe header
    PE32Analysis* infile_analysis = new PE32Analysis(infile);
    if(infile_analysis->error){
        delete infile_analysis;
        delete infile;
        return -1;
    }
    ostreamlog << endl;

    ostreamlog << " -------------------------------" << endl;
    ostreamlog << "| Stage 2: Generating ASM files |" << endl;
    ostreamlog << " -------------------------------" << endl;
    ostreamlog << endl;
    //create opcodes which write the input file into memory
    if(!createFasmInfileArray(infile, key_length, key_space)){
        delete infile_analysis;
        delete infile;
        return -1;
    }

    //create image base asm representation and write it to IMAGE_BASE_INC
    if(!createFasmInclude(IMAGE_BASE_INC, IMAGE_BASE_LABEL, *(infile_analysis->image_base))){
        delete infile_analysis;
        delete infile;
        return -1;
    }

    //create image size asm representation and write it to IMAGE_SIZE_INC
    if(!createFasmInclude(IMAGE_SIZE_INC, IMAGE_SIZE_LABEL, *(infile_analysis->size_of_image))){
        delete infile_analysis;
        delete infile;
        return -1;
    }

    //create an keysize equate for fasm sources
    if(!createFasmKeySize(key_length, key_space)){
        delete infile_analysis;
        delete infile;
        return -1;
    }

    //enable or disble logging framework of output file
    if(!createFasmLogfileInc(create_log)){
        delete infile_analysis;
        delete infile;
        return -1;
    }

    //get current directory
    char* current_directory = new char[3000];
    if(!GetCurrentDirectory(3000, current_directory)){
        cerr<<"Error: Could not receive current directory";
        delete infile_analysis;
        delete infile;
        return 0-1;
    }

    //start fasm to generate a packed executable
    ostreamlog << " --------------------------------" << endl;
    ostreamlog << "| Stage 3: Generating Executable |" << endl;
    ostreamlog << " --------------------------------" << endl;
    ostreamlog << endl;
    string cmd_line = "";
    cmd_line+=FASM_EXECUTABLE;
    cmd_line+=" ";
    cmd_line+=CONTAINER_MAIN;
    cmd_line+=" ";
    cmd_line+=output_name;
    char* cmd_line_noconst = new char[cmd_line.size()+1];
    strcpy(cmd_line_noconst, cmd_line.c_str());

    //init necessary structs for createprocess
    PROCESS_INFORMATION process_info;
    STARTUPINFO startup_info;
    ZeroMemory( &startup_info, sizeof(startup_info) );
    startup_info.cb = sizeof(startup_info);

    //redirect stdin to somewhere else
    if(!display_verbose){
        HANDLE g_hChildStd_OUT_Rd = NULL;
        HANDLE g_hChildStd_OUT_Wr = NULL;
        SECURITY_ATTRIBUTES saAttr;        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        bool cp_ret = CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0);
        bool shi_ret = SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0);
        if ( !cp_ret || !shi_ret ){
            cerr << "Warning: Couldn't create a pipe for FASM output" << endl;
        }
        else{
            startup_info.hStdError = g_hChildStd_OUT_Wr;
            startup_info.hStdOutput = g_hChildStd_OUT_Wr;
            startup_info.dwFlags |= STARTF_USESTDHANDLES;
        }
    }

    ostreamlog<<"Starting FASM with the following parameters:"<<endl;
    ostreamlog<<"Commandline: "<<cmd_line_noconst<<endl;
    ostreamlog<<"FASM Working Directory: " << current_directory <<endl;
    if(!CreateProcess(FASM_EXECUTABLE, cmd_line_noconst, 0, 0,
                     false, 0, 0, current_directory, &startup_info, &process_info)){
        cerr<<"Error: Could not start fasm.exe"<<endl;
        cerr<<"Error Code: "<<GetLastError();
        delete []cmd_line_noconst;
        delete []current_directory;
        delete infile_analysis;
        delete infile;
        return -1;
    }

    //wait for process to terminate
    WaitForSingleObject( process_info.hProcess, INFINITE );

    // Get the exit code
    DWORD exitCode = 0;
    GetExitCodeProcess(process_info.hProcess, &exitCode);
    if(exitCode!=0 && !display_verbose){
        cerr << "FASM returned an error, see --verbose for details" <<endl;
    }
    else if(exitCode==0 && display_verbose){
        cout << endl << "Done :-)" << endl;
    }

    // Close the handles.
    CloseHandle( process_info.hProcess );
    CloseHandle( process_info.hThread );

    //close application
    //ostreamlog << endl;
    delete []cmd_line_noconst;
    delete []current_directory;
    delete infile_analysis;
    delete infile;
    return 0;
}
