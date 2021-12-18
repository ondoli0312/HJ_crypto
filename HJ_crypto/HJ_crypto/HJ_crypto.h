#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

//Parameter Set
#define IN
#define OUT

enum HJCrypto_RESULT {
	success = 0x18900000,
	FAIL_inner_func,
	FAIL_invaild_paramter,
	FAIL_invaild_state,
	FAIL_katselp_test,
	FAIL_critical,
	FAIL_integrity_test
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Src Function
uint32_t HJCrypto_memset(void* pointer, uint32_t value, uint32_t size);

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
	ECB = 0x12000000,
	CTR
};
enum {
	ENCRYPTION = 0x13000000,
	DECRYPTION
};

uint32_t  HJCrypto_BlockCipher(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* in, uint64_t ptLen, const uint8_t* iv, uint8_t* out);
uint32_t  HJCrypto_BlockCipher_init(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* iv);
uint32_t  HJCrypto_BlockCipher_Update(const uint8_t* in, uint64_t ptLen, uint8_t* out, uint64_t* outLen);
uint32_t  HJCrypto_BlockCipher_final(uint8_t* out);
uint32_t  HJCrypto_BlockCipher_Clear(void);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Hash Function API
#define SHA256_BLOCKBYTE	64
#define SHA256_DIGEST_LEN	32
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
uint32_t HJCrypto_Hash(uint32_t Func, const uint8_t* pt, uint64_t ptLen, uint8_t* Digest);
uint32_t HJCrypto_Hash_init(uint32_t Func);
uint32_t HJCrypto_Hash_process(const uint8_t* pt, uint64_t ptLen);
uint32_t HJCrypto_Hash_final(uint8_t* Digest);

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
	uint32_t keyupdate_state;
	uint8_t key[HMAC_SHA256_BLOCKBYTE];
	uint8_t HMAC_IPAD[HMAC_SHA256_DIGEST];
}MAC;

enum {
	HMAC_SHA256 = 0x15000000
};

uint32_t HJCrypto_HMAC(uint32_t func, const uint8_t* key, uint64_t keyLen, const uint8_t* pt, uint64_t ptLen, uint8_t* out);
uint32_t HJCrypto_HMAC_init(uint32_t func, const uint8_t* key, uint64_t keyLen);
uint32_t HJCrypto_HMAC_process(const uint8_t* pt, uint64_t ptLen);
uint32_t HJCrypto_HMAC_final(uint8_t* out);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//CTR-DRBG
#define MAX_ENTROPY_LEN 256
typedef struct {
	uint32_t func;//LEA
	uint8_t V[BLOCKSIZE];
	uint32_t VLen;
	uint8_t key[32];
	uint64_t keyLen;
	uint32_t seedLen;
	uint64_t reseed_cnt;
	uint32_t security_Len;
	uint32_t init_flag;
	uint32_t derivation_func_flag;
	uint32_t prediction_res_flag;
}DRBG;

enum {
	USE_DF = 0x16000000,
	USE_PR,
	NO_DF,
	NO_PR
};
uint32_t HJCrypto_CTR_DRBG_Instantiate(
	uint32_t func, uint32_t keyLen,
	uint8_t* entropy, uint32_t entropyLen,
	uint8_t* nonce, uint32_t nonceLen,
	uint8_t* per_string, uint32_t perLen,
	uint32_t derivation_funcFlag);

uint32_t HJCrypto_CTR_DRBG_Reseed(
	DRBG* info,
	uint8_t* entropy, uint32_t entropyLen,
	uint8_t* add_input, uint32_t addLen);

uint32_t HJCrypto_CTR_DRBG_Generate(
	DRBG* info,
	uint8_t* output, uint64_t req_bitLen, uint8_t* entropy, uint32_t entropyLen,
	uint8_t* add_input, uint32_t addLen, uint32_t prediction_resFlag);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Self-Testing API

//ERROR TYPE
enum {
	KAT_SELFTEST_FAILURE = 0x90100000

};

uint32_t blockCipher_SelfTest_API();
uint32_t Hash_SelfTest_API();
uint32_t HMAC_SelfTest_API();