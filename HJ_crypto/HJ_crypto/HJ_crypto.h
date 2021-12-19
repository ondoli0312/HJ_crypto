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
	FAIL_integrity_test,
	FAIL_entropy_test,
	NOT_katselp_testing,
	FAIL_PERS_LEN_MAX,
};

enum HJCrypto_state_num {
	HJ_LOAD	=	0x17170000,
	HJ_NORMAL,
	HJ_preSELF_test,
	HJ_condition_test,
	HJ_Entropy_test,
	HJ_normal_err,
	HJ_critical_err,
	HJ_exit
};



typedef struct {
	uint32_t blockCipherTest;
	uint32_t HashTest;
	uint32_t HMACTest;
	uint32_t DRBGTest;
}FUNC_TEST;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void HJCrypto_Finish();
void HJCrypto_Load();

//Src Function
uint32_t HJCrypto_memset(void* pointer, uint32_t value, uint32_t size);
uint32_t HJCrypto_getState();
uint32_t HJCrypto_preSelf_Test();
void HJCrypto_Info();

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
	uint64_t ptLen;				//�򹮱���
	uint32_t keyLen;			//Ű����
	uint32_t ENC;				//��ȣȭ�˰���
	uint32_t MODE;				//�����
	uint32_t TYPE;				//��,��ȣȭ
	uint8_t IV[BLOCKSIZE];		//IV Vector
	uint8_t lastBlock[BLOCKSIZE];	//RemainData�� ���� ����
	uint64_t encrypted_len;			//��ȣȭ ���� ����
	uint64_t remain_Len;			//RemainData ���� ���� ����
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

__declspec(dllexport) uint32_t  HJCrypto_BlockCipher(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* in, uint64_t ptLen, const uint8_t* iv, uint8_t* out);
__declspec(dllexport) uint32_t  HJCrypto_BlockCipher_init(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* iv);
__declspec(dllexport) uint32_t  HJCrypto_BlockCipher_Update(const uint8_t* in, uint64_t ptLen, uint8_t* out, uint64_t* outLen);
__declspec(dllexport) uint32_t  HJCrypto_BlockCipher_final(uint8_t* out);
__declspec(dllexport) uint32_t  HJCrypto_BlockCipher_Clear(void);

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
__declspec(dllexport) uint32_t HJCrypto_Hash(uint32_t Func, const uint8_t* pt, uint64_t ptLen, uint8_t* Digest);
__declspec(dllexport) uint32_t HJCrypto_Hash_init(uint32_t Func);
__declspec(dllexport) uint32_t HJCrypto_Hash_process(const uint8_t* pt, uint64_t ptLen);
__declspec(dllexport) uint32_t HJCrypto_Hash_final(uint8_t* Digest);

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

__declspec(dllexport) uint32_t HJCrypto_HMAC(uint32_t func, const uint8_t* key, uint64_t keyLen, const uint8_t* pt, uint64_t ptLen, uint8_t* out);
__declspec(dllexport) uint32_t HJCrypto_HMAC_init(uint32_t func, const uint8_t* key, uint64_t keyLen);
__declspec(dllexport) uint32_t HJCrypto_HMAC_process(const uint8_t* pt, uint64_t ptLen);
__declspec(dllexport) uint32_t HJCrypto_HMAC_final(uint8_t* out);

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

typedef struct {
	uint32_t func;		//HMAC_DRBG
	int32_t EntropyLen;
	int32_t NonceLen;
	int32_t PerLen;
	int32_t reseed_counter;
	int32_t addLen;
	uint32_t PR_flag;
	uint8_t key[SHA256_DIGEST_LEN];
	uint8_t V[SHA256_DIGEST_LEN];
	uint32_t DigestLen;
}HMAC_DRBG;

enum {
	USE_PR = 0x16000000,
	NO_PR
};

__declspec(dllexport) uint32_t HJCrypto_HMAC_DRBG_Instantiate(
	uint32_t func,
	uint8_t* Entropy, uint32_t EntropyLen,
	uint8_t* Nonce, uint32_t NonceLen,
	uint8_t* per_s, uint32_t PerLen,
	uint32_t PR_flag
);

__declspec(dllexport) uint32_t HJCrypto_HMAC_DRBG_Reseed(
	uint8_t* Entropy, uint32_t EntropyLen,
	uint8_t* add, uint32_t addLen
);

__declspec(dllexport) uint32_t HJCrypto_HMAC_DRBG_Generate(
	uint8_t* out, uint32_t outLen,
	uint8_t* Entropy, uint8_t* EntropyLen,
	uint8_t* add, uint8_t* addLen,
	uint32_t PR_flag
);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

uint32_t HMAC_DRBG_SelfTest_API();

//Self-Testing API
uint32_t _DRBG_using(uint8_t* Entropy, uint32_t inLen, uint32_t flag);

//CAVP
void LEA_CTR_MCT();
void LEA_CTR_KAT();
void LEA_CTR_MMT();
void HMAC_DBBG_CAVP();