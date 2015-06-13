#ifndef CREATEOUTPUT_H_INCLUDED
#define CREATEOUTPUT_H_INCLUDED

#include "fileaccess.h"
#include "peanalysis.h"

#define CHECKSUM_SIZE 4
#define KEY_SIZE 6
#define KEY_RANGE 4
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

#define AES_ENCRYPT_API "aesEncrypt"
#define AES_DLL "FasmAES-1.0\\aes10.dll"

namespace hyperion{

    bool createInfileArray(FileInMemory* infile, const char* filename);
    bool createImageBase(PE32Analysis* infile, const char* filename);
    bool createImageSize(PE32Analysis* infile, const char* filename);
    bool createKeySize(const char* filename);
    uint32_t getChecksum(char* data, unsigned int size);
    bool writeFile(const char* filename, const char* content, unsigned long size);
    bool encryptFile(uint8_t* file, unsigned int size);
	bool encryptAES(uint8_t* file, unsigned int size, uint8_t* key);
}

#endif // CREATEOUTPUT_H_INCLUDED
