#include "HJ_crypto.h"
#include "mode core.h"

blockCipher info;

uint32_t HJCrypto_BlockCipher(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* in, uint64_t ptLen, const uint8_t* iv, uint8_t* out) {
	uint32_t ret = success;
	uint32_t p_flag = success;
	uint64_t outLen = 0;

	//parameter Check
	if ((Enc != LEA) || ((mode != CTR) && (mode != ECB)) ||((type != ENCRYPTION) && (type != DECRYPTION))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((masterkey == NULL) || ((keyLen != 16) && (keyLen != 24) && (keyLen != 32))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	//나중에 ECB 탑재하는 경우, iv가 NULL 일 수 있음.
	if ((in == NULL) || (out == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((mode == CTR) && (iv == NULL)) {
		if ((in == NULL) || (out == NULL)) {
			p_flag = FAIL_invaild_paramter;
			goto PERR;
		}
	}

	switch (mode)
	{
	case ECB:
		ret = ECB_init(&info, Enc, masterkey, keyLen, mode, type);
		if (ret != success)
			goto EXIT;
		ret = ECB_update(&info, in, ptLen, out, &outLen);
		if (ret != success)
			goto EXIT;
		ret = ECB_final(&info, out);
		if (ret != success)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_init(&info, Enc, masterkey, keyLen, mode, type, iv);
		if (ret != success)
			goto EXIT;
		ret = CTR_update(&info, in, ptLen, out, &outLen);
		if (ret != success)
			goto EXIT;
		ret = CTR_final(&info, out);
		if (ret != success)
			goto EXIT;
		break;
	default:
		goto EXIT;
		break;
	}
	p_flag = 0;
	outLen = 0;
	return ret;
PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret != success) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher\n");
		fprintf(stdout, "[이유] : Critical ERROR\n");
		ret = FAIL_critical;
		p_flag = 0;
		outLen = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

uint32_t HJCrypto_BlockCipher_init(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* iv) {
	uint32_t ret = success;
	uint32_t p_flag = success;

	//parameter Check
	if ((Enc != LEA) || ((mode != CTR) && (mode != ECB)) || ((type != ENCRYPTION) && (type != DECRYPTION))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((masterkey == NULL) || ((keyLen != 16) && (keyLen != 24) && (keyLen != 32))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//나중에 ECB 탑재하는 경우, iv가 NULL 일 수 있음.
	if ((mode == CTR) && (iv == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	switch (mode)
	{
	case ECB:
		ret = ECB_init(&info, Enc, masterkey, keyLen, mode, type);
		if (ret != success)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_init(&info, Enc, masterkey, keyLen, mode, type, iv);
		if (ret != success)
			goto EXIT;
		break;
	default:
		goto EXIT;
		break;
	}
	return ret;
PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_init\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_init\n");
		fprintf(stdout, "[이유] : Critical Error\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

uint32_t HJCrypto_BlockCipher_Update(const uint8_t* in, uint64_t ptLen, uint8_t* out, uint64_t* outLen) {
	uint32_t ret = success;
	uint32_t p_flag = success;
	//parameter Check
	if ((in == NULL) || (out == NULL) || (outLen == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	switch (info.MODE)
	{
	case ECB:
		ret = ECB_update(&info, in, ptLen, out, &outLen);
		if (ret != success)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_update(&info, in, ptLen, out, &outLen);
		if (ret != success)
			goto EXIT;
		break;
	default:
		goto EXIT;
		break;
	}
	return ret;
PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_Update\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_Update\n");
		fprintf(stdout, "[이유] : Critical Error\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

uint32_t HJCrypto_BlockCipher_final(uint8_t* out) {
	uint32_t ret = success;
	uint32_t p_flag = success;

	//parameter Check
	if ((out == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	switch (info.MODE)
	{
	case ECB:
		ret = ECB_final(&info, out);
		if (ret != success)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_final(&info, out);
		if (ret != success)
			goto EXIT;
		break;
	default:
		break;
	}
	return ret;
PERR:
	if (p_flag != success) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_final\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_final\n");
		fprintf(stdout, "[이유] : Critical Error\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

uint32_t HJCrypto_BlockCipher_Clear(void) {
	uint32_t ret = success;
	ret = HJCrypto_memset(&info, 0, sizeof(blockCipher));
	return ret;
}