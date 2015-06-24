#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string.h>
#include <windows.h>
#include <time.h>

#include "hyperion.h"
#include "createoutput.h"

using namespace std;
using namespace hyperion;

extern OstreamLog ostreamlog;

namespace hyperion{

    /**
     * Declares a FASM constant
     * Output: "<label> equ <value>"
     */
    bool createFasmInclude(const char* filename, const char* label, uint32_t value){
        string fasm_output;
        fasm_output+=label;
        fasm_output+=" equ 0x";
        ostringstream sin;
        sin << hex << value;
        fasm_output+=sin.str();

        //write outout to a file
        if(!writeFile(filename, fasm_output.c_str(), fasm_output.length())){
            cerr << "Error: Couldn't write into " << filename << endl;
            return false;
        }
        else{
            ostreamlog << label << " equ " << hex << "0x" << value <<" written into file:"
            << endl << "-> " << filename << endl << endl;
            return true;
        }
    }


    /**
     * Includes logfile_enable.asm or
     * logfile_disable.asm in the container
     * depending on create_log.
     */

     bool createFasmLogfileInc(bool create_log){
        string fasm_output;
        if(create_log){
            fasm_output+="include 'logfile_enable.asm'";
        }
        else{
            fasm_output+="include 'logfile_disable.asm'";
        }

        //write outout to a file
        if(!writeFile(LOGFILE_SELECT_INC, fasm_output.c_str(), fasm_output.length())){
            cerr << "Error: Couldn't write into " << LOGFILE_SELECT_INC << endl;
            return false;
        }
        else if(create_log){
            ostreamlog << "Enabled log file support in:"
            << endl << "-> " << LOGFILE_SELECT_INC << endl << endl;
            return true;
        }
        else {
            ostreamlog << "Disabled log file support in:"
            << endl << "-> " << LOGFILE_SELECT_INC << endl << endl;
            return true;
        }
    }

    /**
     * Writes the key size of the input file in the asm
     * source as:
	 * "REAL_KEY_SIZE equ <keysize>"
	 * "REAL_KEY_RANGE equ <range>"
     */
    bool createFasmKeySize(unsigned int length, unsigned int space){
        string fasm_output;
        fasm_output+="REAL_KEY_SIZE equ ";
        ostringstream sin;
        sin << length;
        fasm_output+=sin.str();
		fasm_output+="\r\nREAL_KEY_RANGE equ ";
		sin.seekp(0, ios_base::beg);
		sin << space;
		fasm_output+=sin.str();

        //write outout to a file
        if(!writeFile(KEY_SIZE_INC, fasm_output.c_str(), fasm_output.length())){
            cerr << "Error: Couldn't write into " << KEY_SIZE_INC << endl;
            return false;
        }
        else{
            ostreamlog << "Written keysize to:"
            << endl << "-> " << KEY_SIZE_INC << endl << endl;
            return true;
        }
    }

    /**
     * Calculates the checksum of infile, encrypts checksum+infile,
     * converts checksum+infile to
     * a fasm byte array and writes it to filename
     */
    bool createFasmInfileArray(FileInMemory* infile, unsigned int length,
                                unsigned int space){
		//the encrypted file has to be a multiple of the key size
		static unsigned int rounded_infile_size = infile->size+CHECKSUM_SIZE;
		rounded_infile_size+=AES_BLOCK_SIZE - (rounded_infile_size%AES_BLOCK_SIZE);
		ostreamlog<<"Input file size + Checksum: 0x" << hex << infile->size+CHECKSUM_SIZE << dec << endl;
		ostreamlog<<"Rounded up to a multiple of key size: 0x" << hex << rounded_infile_size << dec << endl;
        //reserve memory for the encrypted file in fasm container
		createFasmInclude(INFILE_SIZE_INC, INFILE_SIZE_LABEL, rounded_infile_size);

        //allocate memory for checksum+infile for a complete encryption
        uint8_t* encrypted_input = new uint8_t[rounded_infile_size];
		ZeroMemory(encrypted_input, rounded_infile_size);
        //copy the input file to encrypted_input
        memcpy(&(encrypted_input[CHECKSUM_SIZE]), infile->adress, infile->size);

        //get the checksum and copy it to encrypted_input
        uint32_t checksum = getChecksum(infile->adress, infile->size);
        ostreamlog<<"Generated Checksum: 0x"<<hex<<checksum<<dec<<endl;
        uint32_t* encrypted_input_32 = (uint32_t*) encrypted_input;
        *encrypted_input_32 = checksum;

        //Encryption here
		if(!encryptFile(encrypted_input, rounded_infile_size, length, space)){
            return false;
		}
		ostreamlog<<endl;

		//fasm byte array which contains the encrypted file
        string fasm_output;
        fasm_output+="db ";
        //write the file
        for(unsigned int i=0;i<rounded_infile_size;i++){
            ostringstream sin;
            sin << hex << (unsigned int) (unsigned char) encrypted_input[i];
            fasm_output+="0x";
            fasm_output+=sin.str();
            if(i!=(rounded_infile_size-1)) fasm_output+=", ";
            if(i!=0 && i%10==0) fasm_output+="\\\r\n";
        }

        delete[] encrypted_input;

        if(!writeFile(INFILE_ARRAY, fasm_output.c_str(), fasm_output.length())){
            cerr << "Error: Couldn't write into " << INFILE_ARRAY << endl;
            return false;
        }
        else{
            ostreamlog << "Written encrypted input file as FASM array to:"
            << endl << "-> " << INFILE_ARRAY << endl << endl;
            return true;
        }
    }

    /**
     * Calculates the checksum of infile, encrypts checksum+infile,
     * converts checksum+infile to a fasm "memory loading code"
     * and writes it to INFILE_CODE. Furthermore, fasm code is
     * created which reserves enough memory in the data section.
     */
    bool createFasmInfileLoader(FileInMemory* infile, unsigned int length,
                                unsigned int space){
		//the encrypted file has to be a multiple of the key size
		static unsigned int rounded_infile_size = infile->size+CHECKSUM_SIZE;
		rounded_infile_size+=AES_BLOCK_SIZE - (rounded_infile_size%AES_BLOCK_SIZE);
		ostreamlog<<"Input file size + Checksum: 0x" << hex << infile->size+CHECKSUM_SIZE << dec << endl;
		ostreamlog<<"Rounded up to a multiple of key size: 0x" << hex << rounded_infile_size << dec << endl;
		//reserve memory for the encrypted file in fasm container
		createFasmInclude(INFILE_SIZE_INC, INFILE_SIZE_LABEL, rounded_infile_size);

        //allocate memory for checksum+infile for a complete encryption
        uint8_t* encrypted_input = new uint8_t[rounded_infile_size];
		ZeroMemory(encrypted_input, rounded_infile_size);
        //copy the input file to encrypted_input
        memcpy(&(encrypted_input[CHECKSUM_SIZE]), infile->adress, infile->size);

        //get the checksum and copy it to encrypted_input
        uint32_t checksum = getChecksum(infile->adress, infile->size);
        ostreamlog<<"Generated Checksum: 0x"<<hex<<checksum<<dec<<endl;
        uint32_t* encrypted_input_32 = (uint32_t*) encrypted_input;
        *encrypted_input_32 = checksum;

        //Encryption here
		if(!encryptFile(encrypted_input, rounded_infile_size, length, space)){
            return false;
        }
		ostreamlog<<endl;

		/*
         * This loop reads each encrypted byte and creates
		 * an output of the following  format:
		 * lea eax, [deastination]
		 * mov [eax+0], first_byte
		 * mov [eax+1], second_byte
		 * ...
		 */
        string fasm_output;
        fasm_output+="proc copyEncryptedToMemory stdcall destination:DWORD \r\n";
        fasm_output+="\tmov eax,[destination] \r\n";
        //write the file
        for(unsigned int i=0;i<rounded_infile_size;i++){
            ostringstream sin;
            ostringstream sin2; //TODO:i know its lame
            fasm_output+="\tmov byte [eax+0x";
            sin2 << hex << (unsigned int) i;
            fasm_output+=sin2.str();
            fasm_output+="], ";
            sin << hex << (unsigned int) (unsigned char) encrypted_input[i];
            fasm_output+="0x";
            fasm_output+=sin.str();
            fasm_output+="\r\n";
        }
        fasm_output+="\tret\r\n";
        fasm_output+="endp;";

        delete[] encrypted_input;

        if(!writeFile(INFILE_CODE, fasm_output.c_str(), fasm_output.length())){
            cerr << "Error: Couldn't write into " << INFILE_CODE << endl;
            return false;
        }
        else{
            ostreamlog << "Written encrypted input file as x86 opcodes to:"
            << endl << "-> " << INFILE_CODE << endl << endl;
            return true;
        }
    }

    /**
     * Create a simple checksum from a file which adds each of its bytes
     */
    uint32_t getChecksum(char* data, unsigned int size){
        uint32_t ret = 0;
        for(unsigned int i=0;i<size;i++){
            uint8_t current = (uint8_t) data[i];
            ret+=(uint32_t) current;
        }
        return ret;
    }

    /**
     * Write output file to disk
     */
    bool writeFile(const char* filename, const char* content, unsigned long size){
        ofstream ofile;
        ofile.open(filename, ofstream::binary);
        if(!ofile.is_open()){
            cerr<<"Error: Could not open output file " << filename << ", aborting..."<<endl;
            return false;
        }
        ofile.write(content, size);
        ofile.close();
        return true;
    }

    /**
     * Generates a random key and encrypts the file
     */
    bool encryptFile(uint8_t* file, unsigned int size,
                     unsigned int length, unsigned int space){
        //generate a random encryption key
        srand ( time(NULL) );
        uint8_t key[AES_KEY_SIZE];
        for(unsigned int i=0;i<AES_KEY_SIZE;i++){
			if(i<length) key[i] = rand() % space;
			else key[i] = 0;
        }
        ostreamlog<<"Generated Encryption Key:";
        for(int i=0;i<AES_KEY_SIZE;i++){
            if(i==6) ostreamlog << endl;
            else ostreamlog << " ";
            ostreamlog<<"0x"<<hex<<(uint32_t) key[i]<<dec;
        }
        ostreamlog<<endl;
        //return encryptXOR(file, size, real_key);
		return encryptAES(file, size, key);
    }

	/**
	 * Encrypts the file with AES. Returns false if an error occured
	 * (e.g. if the AES APIs could not been loaded).
	 */
	bool encryptAES(uint8_t* file, unsigned int size, uint8_t* key){
		//load the dll and the encryption api
		//parameter: size, cleartext, encrypted text, key
		HINSTANCE hDLL = LoadLibrary(AES_DLL);
		if(!hDLL){
			cerr<<"Error: Could not load "<<AES_DLL<<endl;
			return false;
		}
		void (__stdcall *aesEncrypt)(uint32_t, uint8_t*, uint8_t*, uint8_t*) =
			 (void (__stdcall *)(uint32_t, uint8_t*, uint8_t*, uint8_t*)) GetProcAddress(hDLL, AES_ENCRYPT_API);
		if(!aesEncrypt){
			cerr<<"Error: Could not load "<<AES_ENCRYPT_API<<"()"<<endl;
			return false;
		}

		//call the encryption api and do the encryption
		aesEncrypt(size, file, file, key);

		return true;
	}
}
