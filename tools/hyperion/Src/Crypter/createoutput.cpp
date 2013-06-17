#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string.h>
#include <windows.h>
#include <time.h>

#include "createoutput.h"

using namespace std;

namespace hyperion{

    /**
     * Writes the image base of the input file in the asm
     * source as: "format PE GUI 4.0 at  <imagebase>"
     */
    bool createImageBase(PE32Analysis* infile, const char* filename){
        string fasm_output;
        fasm_output+="format PE GUI 4.0 at 0x";
        ostringstream sin;
        sin << hex << *(infile->image_base);
        fasm_output+=sin.str();

        //write outout to a file
        if(!writeFile(filename, fasm_output.c_str(), fasm_output.length())) return false;
        else{
            cout << "Written input file's image base to:"
            << endl << "-> " << filename << endl << endl;
            return true;
        }
    }

    /**
     * Writes the image size of the input file in the asm
     * source as: "db <sizeofimage> dup (?)"
     */
    bool createImageSize(PE32Analysis* infile, const char* filename){
        string fasm_output;
        fasm_output+="db 0x";
        ostringstream sin;
        sin << hex << *(infile->size_of_image);
        fasm_output+=sin.str();
        fasm_output+=" dup (?)";

        //write outout to a file
        if(!writeFile(filename, fasm_output.c_str(), fasm_output.length())) return false;
        else{
            cout << "Written input file's image size to:"
            << endl << "-> " << filename << endl << endl;
            return true;
        }
    }

    /**
     * Writes the key size of the input file in the asm
     * source as: 
	 * "KEY_SIZE equ <keysize>"
	 * "KEY_RANGE equ <range>"
     */
    bool createKeySize(const char* filename){
        string fasm_output;
        fasm_output+="REAL_KEY_SIZE equ ";
        ostringstream sin;
        sin << KEY_SIZE;
        fasm_output+=sin.str();
		fasm_output+="\r\nREAL_KEY_RANGE equ ";
		sin.seekp(0, ios_base::beg);
		sin << KEY_RANGE;
		fasm_output+=sin.str();

        //write outout to a file
        if(!writeFile(filename, fasm_output.c_str(), fasm_output.length())) return false;
        else{
            cout << "Written keysize to:"
            << endl << "-> " << filename << endl << endl;
            return true;
        }
    }

    /**
     * Calculates the checksum of infile, encrypts checksum+infile,
     * converts checksum+infile to
     * a fasm byte array and writes it to filename
     */
    bool createInfileArray(FileInMemory* infile, const char* filename){
		//the encrypted file has to be a multiple of the key size
		static unsigned int rounded_infile_size = infile->size+CHECKSUM_SIZE;
		rounded_infile_size+=AES_BLOCK_SIZE - (rounded_infile_size%AES_BLOCK_SIZE);
		cout<<"Input file size + Checksum: 0x" << hex << infile->size+CHECKSUM_SIZE << dec << endl;
		cout<<"Rounded up to a multiple of key size: 0x" << hex << rounded_infile_size << dec << endl;

        //allocate memory for checksum+infile for a complete encryption
        uint8_t* encrypted_input = new uint8_t[rounded_infile_size];
		ZeroMemory(encrypted_input, rounded_infile_size);
        //copy the input file to encrypted_input
        memcpy(&(encrypted_input[CHECKSUM_SIZE]), infile->adress, infile->size);

        //get the checksum and copy it to encrypted_input
        uint32_t checksum = getChecksum(infile->adress, infile->size);
        cout<<"Generated Checksum: 0x"<<hex<<checksum<<dec<<endl;
        uint32_t* encrypted_input_32 = (uint32_t*) encrypted_input;
        *encrypted_input_32 = checksum;

        //Encryption here
		if(!encryptFile(encrypted_input, rounded_infile_size)) return false;
		cout<<endl;

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

        if(!writeFile(filename, fasm_output.c_str(), fasm_output.length())) return false;
        else{
            cout << "Written encrypted input file as fasm array to:"
            << endl << "-> " << filename << endl << endl;
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
            cout<<"Error: Could not open output file " << filename << ", aborting..."<<endl;
            return false;
        }
        ofile.write(content, size);
        ofile.close();
        return true;
    }

    /**
     * Generates a random key and encrypts the file
     */
    bool encryptFile(uint8_t* file, unsigned int size){
        //generate a random encryption key
        srand ( time(NULL) );
        uint8_t key[AES_KEY_SIZE];
        for(int i=0;i<AES_KEY_SIZE;i++){
			if(i<KEY_SIZE) key[i] = rand() % KEY_RANGE;
			else key[i] = 0;
        }
        cout<<"Generated Encryption Key:";
        for(int i=0;i<AES_KEY_SIZE;i++){cout<<" 0x"<<hex<<(uint32_t) key[i]<<dec;}
        cout<<endl;
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
			cout<<"Error: Could not load "<<AES_DLL<<endl;
			return false;
		}
		void (__stdcall *aesEncrypt)(uint32_t, uint8_t*, uint8_t*, uint8_t*) =
			 (void (__stdcall *)(uint32_t, uint8_t*, uint8_t*, uint8_t*)) GetProcAddress(hDLL, AES_ENCRYPT_API);
		if(!aesEncrypt){
			cout<<"Error: Could not load "<<AES_ENCRYPT_API<<"()"<<endl;
			return false;
		}

		//call the encryption api and do the encryption
		aesEncrypt(size, file, file, key);

		return true;
	}
}
