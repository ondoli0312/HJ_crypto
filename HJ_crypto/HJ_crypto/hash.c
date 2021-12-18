#include "SHA-2 core.h"
#include "HJ_crypto.h"

Hash info;

RET HJCrypto_Hash(uint32_t Func, const uint8_t* pt, uint64_t ptLen, uint8_t* Digest) {
	uint32_t p_flag = SUCCESS;
	RET ret = FAILURE;
	//Parameter Check
	if (Func != sha256) {
		p_flag = FAILURE;
		goto PERR;
	}
	if ((ptLen != 0) && (pt == NULL)) {
		p_flag = FAILURE;
		goto PERR;
	}
	if (Digest == NULL){
		p_flag = FAILURE;
		goto PERR;
	}

	ret = SHA256_init(&info);
	if (ret == FAILURE) {
		goto EXIT;
	}
	ret = SHA256_process(pt, ptLen, &info);
	if (ret == FAILURE){
		goto EXIT;
	}
	ret = SHA256_final(&info, Digest);
	if (ret == FAILURE) {
		goto EXIT;
	}

	return ret;

PERR:
	if (p_flag == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Critical Error\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}

RET HJCrypto_Hash_init(uint32_t Func) {
	uint32_t p_flag = SUCCESS;
	RET ret = FAILURE;
	//Parameter Check
	if (Func != sha256) {
		p_flag = FAILURE;
		goto PERR;
	}

	ret = SHA256_init(&info);
	if (ret == FAILURE)
		goto EXIT;
	return ret;
PERR:
	if (p_flag == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret == FAILURE) {
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}

RET HJCrypto_Hash_process(const uint8_t* pt, uint64_t ptLen) {
	uint32_t p_flag = SUCCESS;
	RET ret = FAILURE;
	//Parameter Check

	if ((ptLen != 0) && (pt == NULL)) {
		p_flag = FAILURE;
		goto PERR;
	}

	ret = SHA256_process(pt, ptLen, &info);
	if (ret == FAILURE)
		goto EXIT;

	return ret;
PERR:
	if (p_flag == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
	return SUCCESS;
EXIT:
	if (ret == FAILURE) {
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}

RET HJCrypto_Hash_final(uint8_t* Digest) {
	uint32_t p_flag = SUCCESS;
	RET ret = FAILURE;
	//Parameter Check
	if (Digest == NULL) {
		p_flag = FAILURE;
		goto PERR;
	}
	ret = SHA256_final(&info, Digest);
	if (ret == FAILURE)
		goto EXIT;

	return ret;
PERR:
	if (p_flag == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
	return SUCCESS;
EXIT:
	if (ret == FAILURE) {
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}