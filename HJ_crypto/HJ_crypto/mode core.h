#pragma once
#include "HJ_crypto.h"
#include "LEA.h"

uint32_t CTR_init(blockCipher* info, uint32_t Enc, const uint8_t* masterkey, uint32_t keyLen, uint32_t mode, uint32_t type, const uint8_t* iv);
uint32_t CTR_update(blockCipher* info, const uint8_t* plaintext, uint64_t ptLen, uint8_t* out, uint64_t* outLen);
uint32_t CTR_final(blockCipher* info, uint8_t* out);

uint32_t ECB_init(blockCipher* info, uint32_t Enc, const uint8_t* masterkey, uint32_t keyLen, uint32_t mode, uint32_t type);
uint32_t ECB_update(blockCipher* info, const uint8_t* plaintext, uint64_t ptLen, uint8_t* out, uint64_t* outLen);
uint32_t ECB_final(blockCipher* info, uint8_t* out);
