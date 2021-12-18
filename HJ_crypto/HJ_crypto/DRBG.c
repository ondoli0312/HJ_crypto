#include "HJ_crypto.h"
#include "DRBG.h"
DRBG info;

uint32_t HJCrypto_CTR_DRBG_Instantiate(
	uint32_t func, uint32_t keyLen,
	uint8_t* entropy, uint32_t entropyLen,
	uint8_t* nonce, uint32_t nonceLen,
	uint8_t* per_string, uint32_t perLen,
	uint32_t derivation_funcFlag)
{
	uint32_t ret = success;
	uint32_t pFlag = success;
	HJCrypto_memset(&info, 0, sizeof(DRBG));

	//parameter Check
	if ((func != LEA)) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((keyLen != 16) && (keyLen != 24) && (keyLen != 32)) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (nonce != NULL && (nonceLen < (keyLen >> 1))) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (((per_string != NULL) && (perLen > (MAX_PER_STRING_LEN >> 3))) || (perLen < 0)) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	switch (derivation_funcFlag)
	{
	case USE_DF:
		if (((entropy != NULL) && (entropyLen < keyLen)) || (entropyLen > MAX_ENTROPY_LEN)) {
			pFlag = FAIL_invaild_paramter;
			goto PERR;
		}
		break;
	case NO_DF:
		if ((entropy != NULL) || (entropyLen < (BLOCKSIZE + keyLen)) || (entropyLen > MAX_ENTROPY_LEN)) {
			pFlag = FAIL_invaild_paramter;
			goto PERR;
		}
		break;
	default:
		pFlag = FAIL_invaild_paramter;
		goto PERR;
		break;
	}

	if (entropy == NULL) {
		uint8_t* entropy_buf = NULL;
		uint32_t entropy_bufLen = MAX_ENTROPY_LEN;
		entropy_buf = (uint8_t*)malloc(entropy_buf, entropy_bufLen);
		HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		ret = CTR_DRBG_Instantiate(&info, func, keyLen, entropy_buf, entropy_bufLen, nonce, nonceLen, per_string, perLen, derivation_funcFlag);
		if (ret != success)
			goto EXIT;
		ret = HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		free(entropy_buf);
		entropy_bufLen = 0;
	}
	else {
		ret = CTR_DRBG_Instantiate(&info, func, keyLen, entropy, entropyLen, nonce, nonceLen, per_string, perLen, derivation_funcFlag);
		if (ret!= success)
			goto EXIT;
	}
	return ret;

PERR:
	//파라미터 오류 리턴하게 바꿔야함
	if (pFlag != success) {
		HJCrypto_memset(&info, 0, sizeof(DRBG));
		return pFlag;
	}

EXIT:
	if (ret != success) {
		//심각한 오류 리턴하게 바꿔야함
		HJCrypto_memset(&info, 0, sizeof(DRBG));
		ret = FAIL_critical;
		return ret;
	}

}

uint32_t HJCrypto_CTR_DRBG_Reseed(
	DRBG* info,
	uint8_t* entropy, uint32_t entropyLen,
	uint8_t* add_input, uint32_t addLen)
{
	uint32_t ret = success;
	uint32_t pFlag = success;

	//check Parameter Check
	if (((add_input != NULL) && (addLen > (MAX_ADD_INPUT_LEN >> 3))) || addLen < 0) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((((entropy != NULL) && ((entropyLen < info->keyLen))) || (entropyLen) > (MAX_ENTROPY_LEN << 3))) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (info->init_flag != DRBG_INIT_FLAG) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}

	if (entropy == NULL) {
		uint8_t* entropy_buf = NULL;
		uint32_t entropy_bufLen = MAX_ENTROPY_LEN;
		entropy_buf = (uint8_t*)malloc(entropy_buf, entropy_bufLen);
		HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		ret = CTR_DRBG_Reseed(&info, entropy_buf, entropy_bufLen, add_input, addLen);
		if (ret != success)
			goto EXIT;
		ret = HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		free(entropy_buf);
		entropy_bufLen = 0;
	}
	else
	{
		ret = CTR_DRBG_Reseed(&info, entropy, entropyLen, add_input, addLen);
		if (ret != success) {
			goto EXIT;
		}
	}
	return ret;

PERR:
	//파라미터 오류 정의로 바꿔야하함
	if (pFlag != success) {
		HJCrypto_memset(&info, 0, sizeof(DRBG));
		return pFlag;
	}
EXIT:
	if (ret != success) {
		//심각한 오류로 바꿔야하함]
		HJCrypto_memset(&info, 0, sizeof(DRBG));
		ret = FAIL_critical;
		return ret;
	}
}

uint32_t HJCrypto_CTR_DRBG_Generate(
	DRBG* info,
	uint8_t* output, uint64_t req_bitLen, uint8_t* entropy, uint32_t entropyLen,
	uint8_t* add_input, uint32_t addLen, uint32_t prediction_resFlag)
{
	uint32_t ret = success;
	uint32_t pFlag = success;

	//Check Parameters
	if ((output == NULL) || (req_bitLen < 0) || ((req_bitLen >> 3) > MAX_RAND_BYTE_LEN)) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((prediction_resFlag != USE_PR) && (prediction_resFlag != NO_PR)) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (((add_input != NULL) && (addLen > (MAX_ADD_INPUT_LEN >> 3))) || (addLen < 0)) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (((entropy != NULL) && (entropyLen < info->keyLen)) || (entropyLen > MAX_ENTROPY_LEN)) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (info->init_flag != DRBG_INIT_FLAG) {
		pFlag = FAIL_invaild_paramter;
		goto PERR;
	}

	if ((entropy == NULL) && (prediction_resFlag == USE_PR)) {
		uint8_t* entropy_buf = NULL;
		uint32_t entropy_bufLen = MAX_ENTROPY_LEN;
		entropy_buf = (uint8_t*)malloc(entropy_buf, entropy_bufLen);
		HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		ret = CTR_DRBG_Generate(&info, output, req_bitLen, entropy_buf, entropy_bufLen, add_input, addLen, prediction_resFlag);
		if (ret != success)
			goto EXIT;
		ret = HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		free(entropy_buf);
		entropy_bufLen = 0;
	}
	else {
		ret = CTR_DRBG_Generate(info, output, req_bitLen, entropy, entropyLen, add_input, addLen, prediction_resFlag);
		if (ret != success)
			goto EXIT;
	}
	return ret;
PERR:
	if (pFlag != success) {
		HJCrypto_memset(&info, 0, sizeof(DRBG));
		return pFlag;
	}
EXIT:
	if (ret != success) {
		HJCrypto_memset(&info, 0, sizeof(DRBG));
		ret = FAIL_critical;
		return ret;
	}
}