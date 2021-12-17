#pragma once
#include "HJ_crypto.h"

RET HMAC_init(MAC* info, uint32_t func, const uint8_t* key, uint64_t keyLen);
RET HMAC_process(MAC* info, const uint8_t* pt, uint64_t ptLen);
RET HMAC_final(MAC* info, uint8_t* out);
