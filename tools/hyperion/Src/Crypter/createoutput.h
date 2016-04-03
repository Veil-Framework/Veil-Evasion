#ifndef CREATEOUTPUT_H_INCLUDED
#define CREATEOUTPUT_H_INCLUDED

#include "fileaccess.h"
#include "peanalysis.h"

#define CHECKSUM_SIZE 4
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

#define AES_ENCRYPT_API "aesEncrypt"
#define AES_DLL "FasmAES-1.0\\aes10.dll"

namespace hyperion{
    bool createFasmInfileLoader(FileInMemory* infile,
                                unsigned length, unsigned space);
    bool createFasmInfileArray(FileInMemory* infile, unsigned int length,
                                unsigned int space);
    bool createFasmInclude(const char* filename, const char* label, uint32_t value);
    bool createFasmKeySize(unsigned int length, unsigned int space);
    bool createFasmLogfileInc(bool create_log);

    uint32_t getChecksum(char* data, unsigned int size);

    bool writeFile(const char* filename, const char* content, unsigned long size);
    bool encryptFile(uint8_t* file, unsigned int size,
                     unsigned int length, unsigned int space);
	bool encryptAES(uint8_t* file, unsigned int size, uint8_t* key);
}

#endif // CREATEOUTPUT_H_INCLUDED
