#pragma once
#include "HJ_crypto.h"

#define SEEDLEN_16 32
#define SEEDLEN_24 40
#define SEEDLEN_32 64

#define MAX_V_LEN_IN_BYTES		16
#define MAX_Key_LEN_IN_BYTES	32
#define MAX_SEEDLEN_IN_BYTES	48

#define MAX_NUM_OF_BYTES_TO_RETURN 64
#define SIZE_INT					4

#define MAX_BLOCKCIPHER_KEY_LEN		32

#define DRBG_INIT_FLAG				0x00FF0000
#define MAX_REESED_CTR_LEN			0x1000000000000
#define MAX_PER_STRING_LEN			0x100000000
#define MAX_ADD_INPUT_LEN			0x100000000
#define MAX_RAND_BYTE_LEN			2048
uint32_t CTR_DRBG_Instantiate(DRBG* info, uint32_t func, uint32_t keyLen, uint8_t* entropy, uint32_t entropyLen, uint8_t* nonce, uint32_t nonceLen, uint8_t* per_string, uint32_t perLen, uint32_t derivation_funcFlag);
uint32_t CTR_DRBG_Reseed(DRBG* info, uint8_t* entropy, uint32_t entropyLen, uint8_t* add_input, uint32_t addLen);
uint32_t CTR_DRBG_Generate(DRBG* info, uint8_t* output, uint64_t request_bitLen, uint8_t* entropy, uint64_t entroyLen, uint8_t* add_input, uint32_t addLen, uint32_t prediction_resistance_flag);

uint32_t HMAC_DRBG_instantiate(
	HMAC_DRBG* info, uint32_t func,
	uint8_t* Entropy, uint32_t EntropyLen,
	uint8_t* Nonce, uint32_t NonceLen,
	uint8_t* per_s, uint32_t perLen,
	uint32_t PR_flag
);

uint32_t HMAC_DRBG_reseed(
	HMAC_DRBG* info,
	uint8_t* Entropy, uint32_t EntropyLen,
	uint8_t* add, uint32_t addLen
);

uint32_t HMAC_DRBG_Generate(
	HMAC_DRBG* info,
	uint8_t* out, uint32_t outLen,
	uint8_t* Entropy, uint8_t* EntropyLen,
	uint8_t* add, uint8_t* addLen,
	uint32_t PR_flag
);

