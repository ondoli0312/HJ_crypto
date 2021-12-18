#include "HJ_crypto.h"
#include "HMAC-SHA.h"
MAC info;

uint32_t HJCrypto_HMAC(uint32_t func, const uint8_t* key, uint64_t keyLen, const uint8_t* pt, uint64_t ptLen, uint8_t* out){
	uint32_t p_flag = success;
	uint32_t ret = success;
	
	//Parameter Check
	if (func != HMAC_SHA256) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((key == NULL) || (pt == NULL) || (out == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((keyLen == 0) || (ptLen == 0) ) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//Processing
	ret = HMAC_init(&info, func, key, keyLen);
	if (ret != success) {
		goto EXIT;
	}
	ret = HMAC_process(&info, pt, ptLen);
	if (ret != success) {
		goto EXIT;
	}
	ret = HMAC_final(&info, out);
	if (ret != success) {
		goto EXIT;
	}
	return ret;
PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_HMAC\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return ret;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return ret;
	}
}

uint32_t HJCrypto_HMAC_init(uint32_t func, const uint8_t* key, uint64_t keyLen) {
	uint32_t p_flag = success;
	uint32_t ret = success;

	//Parameter Check
	if (func != HMAC_SHA256) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((key == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((keyLen == 0)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//Processing
	ret = HMAC_init(&info, func, key, keyLen);
	if (ret != success) {
		goto EXIT;
	}

PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_HMAC_init\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return ret;
	}
EXIT:
	if (ret != success) {
		ret = ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return ret;
	}
}

uint32_t HJCrypto_HMAC_process(const uint8_t* pt, uint64_t ptLen) {
	uint32_t p_flag = success;
	uint32_t ret = success;

	//Parameter Check
	if ((pt == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((ptLen == 0)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//Processing
	ret = HMAC_process(&info, pt, ptLen);
	if (ret != success) {
		goto EXIT;
	}

PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_HMAC_process\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return ret;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return ret;
	}
}

uint32_t HJCrypto_HMAC_final(uint8_t* out) {
	uint32_t p_flag = success;
	uint32_t ret = success;

	//Parameter Check
	if ((out == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//Processing
	ret = HMAC_final(&info, out);
	if (ret != success) {
		goto EXIT;
	}

PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_HMAC_final\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return ret;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return ret;
	}
}