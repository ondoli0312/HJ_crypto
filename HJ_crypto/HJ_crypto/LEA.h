#pragma once
#include "type.h"
typedef struct lea_key_st
{
	uint32_t rk[192];
	uint32_t round;
}LEA_KEY;


#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))
#define loadU32(v)	((unsigned int)((((unsigned char*)(&v))[3]<<24)|(((unsigned char*)(&v))[2]<<16)|(((unsigned char*)(&v))[1]<<8)|(((unsigned char*)(&v))[0])))
RET LEA_roundkeyGen(LEA_KEY* key, const uint8_t* mk, uint32_t mk_len);
RET LEA_encryption(const uint8_t* pt, const LEA_KEY* key, uint8_t* ct);
RET LEA_decryption(uint8_t* pt, const LEA_KEY* key, const uint8_t* ct);