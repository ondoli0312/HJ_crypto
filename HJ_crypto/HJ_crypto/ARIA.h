#include "type.h"

#define ARIA_BLOCKBYTE 16

typedef struct ARIA_key_st {
	uint32_t rounds;
	uint8_t roundkeys[ARIA_BLOCKBYTE * 17];
}ARIA_KEY;

RET ARIA_EncKeySetup(const uint8_t* w0, int keyBits, ARIA_KEY* key);
RET ARIA_DecKeySetup(const uint8_t* w0, int keyBits, ARIA_KEY* key);
RET ARIA_encryption(const uint8_t* pt, const ARIA_KEY* key, uint8_t* out);