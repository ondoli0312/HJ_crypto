#include "HJ_crypto.h"
#include "mode core.h"

blockCipher info;

RET HJCrypto_BlockCipher(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* in, uint64_t ptLen, const uint8_t* iv, uint8_t* out) {
	RET ret = FAILURE;
	RET p_flag = 0;
	uint64_t outLen = 0;

	//parameter Check
	if ((Enc != LEA) || ((mode != CTR) && (mode != ECB)) ||((type != ENCRYPTION) && (type != DECRYPTION))) {
		p_flag = FAILURE;
		goto PERR;
	}
	if ((masterkey == NULL) || ((keyLen != 16) && (keyLen != 24) && (keyLen != 32))) {
		p_flag = FAILURE;
		goto PERR;
	}
	//나중에 ECB 탑재하는 경우, iv가 NULL 일 수 있음.
	if ((in == NULL) || (out == NULL)) {
		p_flag = FAILURE;
		goto PERR;
	}
	if ((mode == CTR) && (iv == NULL)) {
		if ((in == NULL) || (out == NULL)) {
			p_flag = FAILURE;
			goto PERR;
		}
	}

	switch (mode)
	{
	case ECB:
		ret = ECB_init(&info, Enc, masterkey, keyLen, mode, type);
		if (ret == FAILURE)
			goto EXIT;
		ret = ECB_update(&info, in, ptLen, out, &outLen);
		if (ret == FAILURE)
			goto EXIT;
		ret = ECB_final(&info, out);
		if (ret == FAILURE)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_init(&info, Enc, masterkey, keyLen, mode, type, iv);
		if (ret == FAILURE)
			goto EXIT;
		ret = CTR_update(&info, in, ptLen, out, &outLen);
		if (ret == FAILURE)
			goto EXIT;
		ret = CTR_final(&info, out);
		if (ret == FAILURE)
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
	if (p_flag == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return ret;
	}
EXIT:
	if (ret == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher\n");
		fprintf(stdout, "[이유] : Critical ERROR\n");
		ret = FAILURE;
		p_flag = 0;
		outLen = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
	return ret;
}

RET HJCrypto_BlockCipher_init(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* iv) {
	RET ret = FAILURE;
	RET p_flag = 0;

	//parameter Check
	if ((Enc != LEA) || ((mode != CTR) && (mode != ECB)) || ((type != ENCRYPTION) && (type != DECRYPTION))) {
		p_flag = FAILURE;
		goto PERR;
	}
	if ((masterkey == NULL) || ((keyLen != 16) && (keyLen != 24) && (keyLen != 32))) {
		p_flag = FAILURE;
		goto PERR;
	}

	//나중에 ECB 탑재하는 경우, iv가 NULL 일 수 있음.
	if ((mode == CTR) && (iv == NULL)) {
		p_flag = FAILURE;
		goto PERR;
	}

	switch (mode)
	{
	case ECB:
		ret = ECB_init(&info, Enc, masterkey, keyLen, mode, type);
		if (ret == FAILURE)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_init(&info, Enc, masterkey, keyLen, mode, type, iv);
		if (ret == FAILURE)
			goto EXIT;
		break;
	default:
		goto EXIT;
		break;
	}
	return ret;
PERR:
	if (p_flag == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_init\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return ret;
	}
EXIT:
	if (ret == FAILURE) {
		ret = FAILURE;
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_init\n");
		fprintf(stdout, "[이유] : Critical Error\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

RET HJCrypto_BlockCipher_Update(const uint8_t* in, uint64_t ptLen, uint8_t* out, uint64_t* outLen) {
	RET ret = FAILURE;
	RET p_flag = 0;
	//parameter Check
	if ((in == NULL) || (out == NULL) || (outLen == NULL))
		goto PERR;
	switch (info.MODE)
	{
	case ECB:
		ret = ECB_update(&info, in, ptLen, out, &outLen);
		if (ret == FAILURE)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_update(&info, in, ptLen, out, &outLen);
		if (ret == FAILURE)
			goto EXIT;
		break;
	default:
		goto EXIT;
		break;
	}
	return ret;
PERR:
	if (p_flag == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_Update\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return ret;
	}
EXIT:
	if (ret == FAILURE) {
		ret = FAILURE;
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_Update\n");
		fprintf(stdout, "[이유] : Critical Error\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

RET HJCrypto_BlockCipher_final(uint8_t* out) {
	RET ret = FAILURE;
	RET p_flag = 0;

	//parameter Check
	if ((out == NULL))
		goto PERR;

	switch (info.MODE)
	{
	case ECB:
		ret = ECB_final(&info, out);
		if (ret == FAILURE)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_final(&info, out);
		if (ret == FAILURE)
			goto EXIT;
		break;
	default:
		break;
	}
	return ret;
PERR:
	if (p_flag == FAILURE) {
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_final\n");
		fprintf(stdout, "[이유] : Parameter Error\n");
		return ret;
	}
EXIT:
	if (ret == FAILURE) {
		ret = FAILURE;
		fprintf(stdout, "[위치] : HJCrypto_BlockCipher_final\n");
		fprintf(stdout, "[이유] : Critical Error\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

RET HJCrypto_BlockCipher_Clear(void) {
	RET ret = FAILURE;
	ret = HJCrypto_memset(&info, 0, sizeof(blockCipher));
	return ret;
}