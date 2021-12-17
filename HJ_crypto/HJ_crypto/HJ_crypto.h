#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

//Parameter Set
typedef bool RET;
#define IN
#define OUT
#define SUCCESS 1
#define FAILURE 0
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Src Function
RET HJCrypto_memset(void* pointer, uint32_t value, uint32_t size);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//BlockCipher API
#define BLOCKSIZE 16
typedef struct lea_key_st
{
	uint32_t rk[192];
	uint32_t round;
}LEA_KEY;

typedef struct {
	uint64_t ptLen;				//평문길이
	uint32_t keyLen;			//키길이
	uint32_t ENC;				//암호화알고리즘
	uint32_t MODE;				//운용모드
	uint32_t TYPE;				//암,복호화
	uint8_t IV[BLOCKSIZE];		//IV Vector
	uint8_t lastBlock[BLOCKSIZE];	//RemainData에 대한 정보
	uint64_t encrypted_len;			//암호화 길이 정보
	uint64_t remain_Len;			//RemainData 남은 길이 정보
	LEA_KEY* LEA_key;
}blockCipher;
enum {
	LEA = 0x11000000
};
enum {
	CTR = 0x12000000
};
enum {
	ENCRYPTION = 0x13000000,
	DECRYPTION
};
RET HJCrypto_BlockCipher(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* in, uint64_t ptLen, const uint8_t* iv, uint8_t* out);
RET HJCrypto_BlockCipher_init(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* iv);
RET HJCrypto_BlockCipher_Update(const uint8_t* in, uint64_t ptLen, uint8_t* out, uint64_t* outLen);
RET HJCrypto_BlockCipher_final(uint8_t* out);
RET HJCrypto_BlockCipher_Clear(void);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Hash Function API
#define SHA256_BLOCKBYTE	64
typedef struct {
	uint32_t func;

	//sha256 API
	uint32_t Digest[8];
	uint64_t ptLen;
	uint8_t	BUF[SHA256_BLOCKBYTE];
	uint32_t lastLen;

}Hash;

enum {
	sha256 = 0x14000000
};
RET HJCrypto_Hash(uint32_t Func, const uint8_t* pt, uint64_t ptLen, uint8_t* Digest);
RET HJCrypto_Hash_init(uint32_t Func);
RET HJCrypto_Hash_process(const uint8_t* pt, uint64_t ptLen);
RET HJCrypto_Hash_final(uint8_t* Digest);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//HMAC API
#define HMAC_SHA256_BLOCKBYTE 64
#define HMAC_SHA256_DIGEST 32
typedef struct {
	Hash hash_info;
	uint32_t func;
	uint32_t keyLen;
	RET keyupdate_state;
	uint8_t key[HMAC_SHA256_BLOCKBYTE];
	uint8_t HMAC_IPAD[HMAC_SHA256_DIGEST];
}MAC;

enum {
	HMAC_SHA256 = 0x15000000
};

RET HJCrypto_HMAC(uint32_t func, const uint8_t* key, uint64_t keyLen, const uint8_t* pt, uint64_t ptLen, uint8_t* out);
RET HJCrypto_HMAC_init(uint32_t func, const uint8_t* key, uint64_t keyLen);
RET HJCrypto_HMAC_process(const uint8_t* pt, uint64_t ptLen);
RET HJCrypto_HMAC_final(uint8_t* out);


//CTR-DRBG API

//KCDSA API


//Self-Testing API

