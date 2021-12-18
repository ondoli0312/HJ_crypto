#pragma once
#include "HJ_crypto.h"

#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))
#define loadU32(v)	((unsigned int)((((unsigned char*)(&v))[3]<<24)|(((unsigned char*)(&v))[2]<<16)|(((unsigned char*)(&v))[1]<<8)|(((unsigned char*)(&v))[0])))
uint32_t LEA_roundkeyGen(LEA_KEY* key, const uint8_t* mk, uint32_t mk_len);
uint32_t LEA_encryption(const uint8_t* pt, const LEA_KEY* key, uint8_t* ct);
uint32_t LEA_decryption(uint8_t* pt, const LEA_KEY* key, const uint8_t* ct);