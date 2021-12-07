#include "SHA-2 core.h"
#include "HJ_crypto.h"

RET HJ_crypto_SHA256(uint8_t* pt, uint64_t byteLen, uint8_t* out) {
	SHA256_INFO info;
	RET ret = FAILURE;
	ret = SHA256_init(&info);
	if (ret != SUCCESS)
		return FAILURE;
	ret = SHA256_process(pt, byteLen, &info);
	if (ret != SUCCESS)
		return FAILURE;
	ret = SHA256_final(&info, out);
	if (ret != SUCCESS)
		return FAILURE;
	return ret;
}

RET HJ_crypto_SHA512(uint8_t* pt, uint64_t byteLen, uint8_t* out) {
	SHA512_INFO info;
	RET ret = FAILURE;
	ret = SHA512_init(&info);
	if (ret != SUCCESS)
		return FAILURE;
	ret = SHA512_process(pt, byteLen, &info);
	if (ret != SUCCESS)
		return FAILURE;
	ret = SHA512_final(&info, out);
	if (ret != SUCCESS)
		return FAILURE;
	return ret;
}