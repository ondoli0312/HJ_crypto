#include "SHA-2 core.h"
#include "HJ_crypto.h"

Hash info;

uint32_t HJCrypto_Hash(uint32_t Func, const uint8_t* pt, uint64_t ptLen, uint8_t* Digest) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	//Parameter Check
	if (Func != sha256) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((ptLen != 0) && (pt == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (Digest == NULL){
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	ret = SHA256_init(&info);
	if (ret != success) {
		goto EXIT;
	}
	ret = SHA256_process(pt, ptLen, &info);
	if (ret != success) {
		goto EXIT;
	}
	ret = SHA256_final(&info, Digest);
	if (ret != success) {
		goto EXIT;
	}

	return ret;

PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Critical Error\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}

uint32_t HJCrypto_Hash_init(uint32_t Func) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	//Parameter Check
	if (Func != sha256) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	ret = SHA256_init(&info);
	if (ret != success)
		goto EXIT;
	return ret;
PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}

uint32_t HJCrypto_Hash_process(const uint8_t* pt, uint64_t ptLen) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	//Parameter Check

	if ((ptLen != 0) && (pt == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	ret = SHA256_process(pt, ptLen, &info);
	if (ret != success)
		goto EXIT;

	return ret;
PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}

uint32_t HJCrypto_Hash_final(uint8_t* Digest) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	//Parameter Check
	if (Digest == NULL) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	ret = SHA256_final(&info, Digest);
	if (ret != success)
		goto EXIT;

	return ret;
PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_Hash\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret != success) {
		p_flag = 0;
		ret = FAIL_critical;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}