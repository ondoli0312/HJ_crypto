#include "HJ_crypto.h"
#include "DRBG.h"
DRBG info;

RET HJCrypto_CTR_DRBG_Instantiate(
	uint32_t func, uint32_t keyLen,
	uint8_t* entropy, uint32_t entropyLen,
	uint8_t* nonce, uint32_t nonceLen,
	uint8_t* per_string, uint32_t perLen,
	uint32_t derivation_funcFlag)
{
	RET ret = SUCCESS;
	uint32_t pFlag = SUCCESS;
	HJCrypto_memset(&info, 0, sizeof(DRBG));

	//parameter Check
	if ((func != LEA)) {
		pFlag = FAILURE;
		goto PERR;
	}
	if ((keyLen != 16) && (keyLen != 24) && (keyLen != 32)) {
		pFlag = FAILURE;
		goto PERR;
	}
	if (nonce == NULL || (nonceLen < (keyLen >> 1))) {
		pFlag = FAILURE;
		goto PERR;
	}
	if (((per_string != NULL) && (perLen > (MAX_PER_STRING_LEN >> 3))) || (perLen < 0)) {
		pFlag = FAILURE;
		goto PERR;
	}
	switch (derivation_funcFlag)
	{
	case USE_DF:
		if (((entropy != NULL) && (entropyLen < keyLen)) || (entropyLen > MAX_ENTROPY_LEN)) {
			pFlag = FAILURE;
			goto PERR;
		}
		break;
	case NO_DF:
		if ((entropy != NULL) || (entropyLen < (BLOCKSIZE + keyLen)) || (entropyLen > MAX_ENTROPY_LEN)) {
			pFlag = FAILURE;
goto PERR;
		}
		break;
	default:
		pFlag = FAILURE;
		goto PERR;
		break;
	}

	if (entropy == NULL) {
		uint8_t* entropy_buf = NULL;
		uint32_t entropy_bufLen = MAX_ENTROPY_LEN;
		entropy_buf = (uint8_t*)malloc(entropy_buf, entropy_bufLen);
		HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		ret = CTR_DRBG_Instantiate(&info, func, keyLen, entropy_buf, entropy_bufLen, nonce, nonceLen, per_string, perLen, derivation_funcFlag);
		if (ret == FAILURE)
			goto EXIT;
		ret = HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		free(entropy_buf);
		entropy_bufLen = 0;
	}
	else {
		ret = CTR_DRBG_Instantiate(&info, func, keyLen, entropy, entropyLen, nonce, nonceLen, per_string, perLen, derivation_funcFlag);
		if (ret == FAILURE)
			goto EXIT;
	}
	return ret;

PERR:
	//�Ķ���� ���� �����ϰ� �ٲ����
	if (ret == FAILURE) {
		HJCrypto_memset(&info, 0, sizeof(DRBG));
		return ret;
	}

EXIT:
	//�ɰ��� ���� �����ϰ� �ٲ����
	return ret;

}

RET HJCrypto_CTR_DRBG_Reseed(
	DRBG* info,
	uint8_t* entropy, uint32_t entropyLen,
	uint8_t* add_input, uint32_t addLen)
{
	RET ret = FAILURE;
	RET pFlag = FAILURE;

	//check Parameter Check
	if (((add_input != NULL) && (addLen > (MAX_ADD_INPUT_LEN >> 3))) || addLen < 0) {
		pFlag = FAILURE;
		goto PERR;
	}
	if ((((entropy != NULL) && ((entropyLen < info->keyLen))) || (entropyLen) > (MAX_ENTROPY_LEN << 3))) {
		pFlag = FAILURE;
		goto PERR;
	}
	if (info->init_flag != DRBG_INIT_FLAG) {
		pFlag = FAILURE;
		goto PERR;
	}

	if (entropy == NULL) {
		uint8_t* entropy_buf = NULL;
		uint32_t entropy_bufLen = MAX_ENTROPY_LEN;
		entropy_buf = (uint8_t*)malloc(entropy_buf, entropy_bufLen);
		HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		ret = CTR_DRBG_Reseed(&info, entropy_buf, entropy_bufLen, add_input, addLen);
		if (ret == FAILURE)
			goto EXIT;
		ret = HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		free(entropy_buf);
		entropy_bufLen = 0;
	}
	else
	{
		ret = CTR_DRBG_Reseed(&info, entropy, entropyLen, add_input, addLen);
		if (ret == FAILURE) {
			goto EXIT;
		}
	}
	return ret;

PERR:
	//�Ķ���� ���� ���Ƿ� �ٲ������
	if (pFlag == FAILURE) {
		return pFlag;
	}
EXIT:
	//�ɰ��� ������ �ٲ������
	return ret;
}

RET HJCrypto_CTR_DRBG_Generate(
	DRBG* info,
	uint8_t* output, uint64_t req_bitLen, uint8_t* entropy, uint32_t entropyLen,
	uint8_t* add_input, uint32_t addLen, uint32_t prediction_resFlag)
{
	RET ret = FAILURE;
	RET pFlag = FAILURE;

	//Check Parameters
	if ((output == NULL) || (req_bitLen < 0) || ((req_bitLen >> 3) > MAX_RAND_BYTE_LEN)) {
		pFlag = FAILURE;
		goto PERR;
	}
	if ((prediction_resFlag != USE_PR) && (prediction_resFlag != NO_PR)) {
		pFlag = FAILURE;
		goto PERR;
	}
	if (((add_input != NULL) && (addLen > (MAX_ADD_INPUT_LEN >> 3))) || (addLen < 0)) {
		pFlag = FAILURE;
		goto PERR;
	}
	if (((entropy != NULL) && (entropyLen < info->keyLen)) || (entropyLen > MAX_ENTROPY_LEN)) {
		pFlag = FAILURE;
		goto PERR;
	}
	if (info->init_flag != DRBG_INIT_FLAG) {
		pFlag = FAILURE;
		goto PERR;
	}

	if ((entropy == NULL) && (prediction_resFlag == USE_PR)) {
		uint8_t* entropy_buf = NULL;
		uint32_t entropy_bufLen = MAX_ENTROPY_LEN;
		entropy_buf = (uint8_t*)malloc(entropy_buf, entropy_bufLen);
		HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		ret = CTR_DRBG_Generate(&info, output, req_bitLen, entropy_buf, entropy_bufLen, add_input, addLen, prediction_resFlag);
		if (ret == FAILURE)
			goto EXIT;
		ret = HJCrypto_memset(entropy_buf, 0, entropy_bufLen);
		free(entropy_buf);
		entropy_bufLen = 0;
	}
	else {
		ret = CTR_DRBG_Generate(info, output, req_bitLen, entropy, entropyLen, add_input, addLen, prediction_resFlag);
		if (ret == FAILURE)
			goto EXIT;
	}
	return ret;
PERR:
	return pFlag;
EXIT:
	return ret;
}