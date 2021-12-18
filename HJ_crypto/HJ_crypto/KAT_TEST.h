#pragma once

#include "HJ_crypto.h"

enum {
	KAT_SELFTEST_FAILURE = 0x90100000

};

uint32_t _KAT_SELF_TEST();
uint32_t blockCipher_SelfTest_API();
uint32_t Hash_SelfTest_API();
uint32_t HMAC_SelfTest_API();