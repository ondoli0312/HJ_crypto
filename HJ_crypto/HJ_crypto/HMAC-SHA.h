#pragma once
#include "HJ_crypto.h"
#define key_update_DONE		0x15450000
uint32_t HMAC_init(MAC* info, uint32_t func, const uint8_t* key, uint64_t keyLen);
uint32_t HMAC_process(MAC* info, const uint8_t* pt, uint64_t ptLen);
uint32_t HMAC_final(MAC* info, uint8_t* out);
