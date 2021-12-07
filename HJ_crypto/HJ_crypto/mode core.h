#pragma once
#include "type.h"
#include "ARIA.h"
#include "LEA.h"

#define BLOCKSIZE 16

typedef struct {
	uint64_t ptLen;
	uint32_t keyLen;
	uint32_t ENC;
	uint32_t MODE;
	uint32_t TYPE;
	uint8_t IV[BLOCKSIZE];
	uint8_t lastBlock[BLOCKSIZE];
	uint64_t encrypted_len;
	LEA_KEY* LEA_key;
	ARIA_KEY* ARIA_key;
}blockCipher;

enum {
	LEA = 0x11000000,
	ARIA
};

enum {
	CBC = 0x71000000,
	CTR
};

enum {
	ENCRYPTION = 0x81000000,
	DECRYPTION
};

