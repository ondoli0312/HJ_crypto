#include "HJ_crypto.h"
#include "DRBG.h"

# define octet_to_int(os) (((unsigned int)(os)[0] << 24) ^ ((unsigned int)(os)[1] << 16) ^ ((unsigned int)(os)[2] <<  8) ^ ((unsigned int)(os)[3]))
# define int_to_octet(os, i) { (os)[0] = (unsigned char)((i) >> 24); (os)[1] = (unsigned char)((i) >> 16); (os)[2] = (unsigned char)((i) >>  8); (os)[3] = (unsigned char)(i); }

static void ctr_increase(unsigned char* counter) {
	unsigned int c_byte;
	c_byte = octet_to_int(counter + 12);
	c_byte++;
	c_byte &= 0xFFFFFFFF;
	int_to_octet(counter + 12, c_byte);
	if (c_byte)
		return;
	c_byte = octet_to_int(counter + 8);
	c_byte++;
	c_byte &= 0xFFFFFFFF;
	int_to_octet(counter + 8, c_byte);
	if (c_byte)
		return;
	c_byte = octet_to_int(counter + 4);
	c_byte++;
	c_byte &= 0xFFFFFFFF;
	int_to_octet(counter + 4, c_byte);
	if (c_byte)
		return;
	c_byte = octet_to_int(counter + 0);
	c_byte++;
	c_byte &= 0xFFFFFFFF;
	int_to_octet(counter + 0, c_byte);
}

static RET BCC(uint32_t func, uint8_t* key, uint32_t keyLen, uint8_t* data, uint64_t dataLen, uint8_t* outBlock, uint64_t outLen) {
	uint32_t n = dataLen / outLen;
	uint8_t inputBlock[MAX_V_LEN_IN_BYTES];
	uint64_t i, j, idx = 0;
	RET ret = FAILURE;
	HJCrypto_memset(inputBlock, 0, MAX_V_LEN_IN_BYTES);
	HJCrypto_memset(outBlock, 0, outLen);
	for (i = 1; i <= n; i++) {
		for (j = 0; j < outLen; j++)
			inputBlock[j] = outBlock[j] ^ data[j];
		ret = HJCrypto_BlockCipher(func, ECB, ENCRYPTION, key, keyLen, inputBlock, BLOCKSIZE, NULL, outBlock);
		data += BLOCKSIZE;
	}
	ret = HJCrypto_memset(inputBlock, 0, MAX_V_LEN_IN_BYTES);
	return ret;
}

static RET Blockcipher_df(uint32_t func, uint32_t keyLen, uint8_t* input_string, uint64_t inputLen, uint8_t* out, uint64_t outLen)
{
	uint8_t X[MAX_NUM_OF_BYTES_TO_RETURN];
	uint8_t K[MAX_BLOCKCIPHER_KEY_LEN];
	uint8_t IV[BLOCKSIZE];
	uint8_t block[BLOCKSIZE];
	uint8_t* S = NULL;
	uint8_t* temp = NULL;
	uint8_t* iv_s = NULL;
	uint8_t* ptr = NULL;

	int32_t L = inputLen;
	int32_t N = outLen;
	int32_t KLen = keyLen;
	int32_t i = 0;
	int32_t j = 0;
	int32_t SLen = 0;
	int32_t iv_s_len = 0;
	int32_t tempLen = 0;

	if (outLen > MAX_NUM_OF_BYTES_TO_RETURN) {
		goto EXIT;
	}

	//form S = L || N || input_string || 0x80
	SLen = 8 + inputLen + 1;
	if ((SLen % BLOCKSIZE) != 0) {
		SLen += ((BLOCKSIZE)-(SLen % BLOCKSIZE));
	}
	S = (uint8_t*)malloc(SLen);
	HJCrypto_memset(S, 0, SLen);
	int_to_octet(S, L);
	int_to_octet(S + SIZE_INT, N);
	memcpy(S + SIZE_INT + SIZE_INT, input_string, inputLen);
	S[SIZE_INT + SIZE_INT + inputLen] = 0x80;

	for (j = 0; j < KLen; j++)
		K[j] = j;

	tempLen = (KLen + outLen) + (BLOCKSIZE - ((KLen + outLen) % BLOCKSIZE));
	temp = (uint8_t*)malloc(tempLen);
	ptr = temp;
	iv_s_len = SLen + BLOCKSIZE;
	iv_s = (uint8_t*)malloc(iv_s_len);
	i = 0;
	tempLen = 0;
	while (tempLen < (KLen + outLen)) {
		int_to_octet(IV, i);
		HJCrypto_memset(IV + SIZE_INT, 0, BLOCKSIZE - SIZE_INT);
		memcpy(iv_s, IV, BLOCKSIZE);
		memcpy(iv_s + BLOCKSIZE, S, SLen);

		BCC(func, K, keyLen, iv_s, iv_s_len, block, BLOCKSIZE);
		memcpy(ptr, block, BLOCKSIZE);
		ptr += BLOCKSIZE;
		tempLen += BLOCKSIZE;
		i++;
	}
	memcpy(K, temp, KLen);
	memcpy(X, temp + KLen, outLen);
	HJCrypto_memset(temp, 0, tempLen);
	free(temp);
	temp = (uint8_t*)malloc((outLen)+ (BLOCKSIZE - ((outLen) % BLOCKSIZE)));
	ptr = temp;
	tempLen = 0;
	while (tempLen < outLen) {
		HJCrypto_BlockCipher(func, ECB, ENCRYPTION, K, keyLen, X, BLOCKSIZE, NULL, X);
		memcpy(ptr, X, BLOCKSIZE);
		ptr += BLOCKSIZE;
		tempLen += BLOCKSIZE;
	}
	memcpy(out, temp, outLen);
	return SUCCESS;
EXIT:
	if (S != NULL) {
		memset(S, 0x00, SLen);
		free(S);
	}
	if (temp != NULL) {
		memset(temp, 0x00, tempLen);
		free(temp);
	}
	if (iv_s != NULL) {
		memset(iv_s, 0x00, iv_s_len);
		free(iv_s);
	}
	HJCrypto_memset(X, 0, sizeof(X));
	HJCrypto_memset(K, 0, sizeof(K));
	HJCrypto_memset(IV, 0, sizeof(IV));
	HJCrypto_memset(block, 0, sizeof(block));
	return FAILURE;
}

static RET CTR_DRBG_update(uint8_t* provided_data, DRBG* info) {
	uint8_t temp[MAX_SEEDLEN_IN_BYTES];
	uint8_t* ptr;
	int32_t tempLen = 0;
	int32_t i = 0;
	RET ret = FAILURE;
	HJCrypto_memset(temp, 0, MAX_SEEDLEN_IN_BYTES);
	if (provided_data == NULL)
		goto EXIT;
	ptr = temp;
	while (tempLen < info->seedLen) {
		ctr_increase(info->V);
		HJCrypto_BlockCipher(info->func, ECB, ENCRYPTION, info->key, info->keyLen, info->V, BLOCKSIZE, NULL, ptr);
		ptr += BLOCKSIZE;
		tempLen += BLOCKSIZE;
	}
	for (i = 0; i < info->seedLen; i++)
		temp[i] ^= provided_data[i];
	memcpy(info->key, temp, info->keyLen);
	ptr = temp;
	memcpy(info->V, ptr + (info->seedLen) - (info->VLen), info->VLen);
	ret = HJCrypto_memset(temp, 0, sizeof(temp));
	ptr = NULL;
	tempLen = 0;
	i = 0;
	return ret;
EXIT:
	if (ret == FAILURE) {
		HJCrypto_memset(info, 0, sizeof(DRBG));
		ptr = NULL;
		HJCrypto_memset(temp, 0, sizeof(temp));
		return ret;
	}
}

RET CTR_DRBG_Instantiate(DRBG* info, uint32_t func, uint32_t keyLen, uint8_t* entropy, uint32_t entropyLen, uint8_t* nonce, uint32_t nonceLen, uint8_t* per_string, uint32_t perLen, uint32_t derivation_funcFlag){
	uint8_t seed_material[MAX_SEEDLEN_IN_BYTES];
	uint8_t seed_material_in = NULL;
	uint8_t* ptr = NULL;
	int32_t seed_material_Len = 0;
	int32_t i = 0;
	RET ret = FAILURE;

	HJCrypto_memset(info, 0, sizeof(DRBG));
	
	if (derivation_funcFlag == USE_DF)
		info->derivation_func_flag = USE_DF;
	else
		info->derivation_func_flag = NO_DF;
	
	if (info->derivation_func_flag == USE_DF) {
		HJCrypto_memset(seed_material, 0, MAX_SEEDLEN_IN_BYTES);
		seed_material_Len = entropyLen;
		if (nonce != NULL && nonceLen > 0)
			seed_material_Len += (nonceLen);
		if (per_string != NULL && perLen > 0)
			seed_material_Len += (perLen);
		ptr = seed_material_in = (uint8_t*)malloc(seed_material_Len);
		memcpy(ptr, entropy, entropyLen);
		if (nonce != NULL && nonceLen > 0) {
			ptr += entropyLen;
			memcpy(ptr, nonce, nonceLen);
		}
		if (per_string != NULL && perLen > 0) {
			ptr += entropyLen;
			memcpy(ptr, per_string, perLen);
		}
		if (Blockcipher_df(func, keyLen, seed_material_in, seed_material_Len, seed_material, info->seedLen) != SUCCESS) {
			HJCrypto_memset(seed_material, 0, info->seedLen);
			ret = FAILURE;
			goto EXIT;
		}

	}
	else {
		i = perLen <= entropyLen ? perLen : entropyLen;
		if (i > MAX_SEEDLEN_IN_BYTES)
			i = MAX_SEEDLEN_IN_BYTES;
		HJCrypto_memset(seed_material, 0, MAX_SEEDLEN_IN_BYTES);
		if (per_string == NULL || perLen == 0) {
			for (int32_t j = 0; j < entropyLen; j++)
				seed_material[j] = entropy[j];
		}
		else {
			for (int32_t j = 0; j < i; j++)
				seed_material[j] = entropy[j] ^ per_string[j];
		}
	}

	HJCrypto_memset(info->key, 0, MAX_Key_LEN_IN_BYTES);
	HJCrypto_memset(info->V, 0, MAX_V_LEN_IN_BYTES);

	if (CTR_DRBG_update(seed_material, info) != SUCCESS) {
		HJCrypto_memset(seed_material, 0, info->seedLen);
		ret = FAILURE;
		goto EXIT;
	}
	info->reseed_cnt = 1;
	info->init_flag = DRBG_INIT_FLAG;
	HJCrypto_memset(seed_material, 0, sizeof(seed_material));
	HJCrypto_memset(seed_material_in, 0, sizeof(seed_material_in));
	HJCrypto_memset(ptr, 0, sizeof(ptr));
	seed_material_in = NULL;
	ptr = NULL;
	seed_material_Len = 0;
	i = 0;
	return SUCCESS;
EXIT:
	if (ret != SUCCESS) {
		HJCrypto_memset(info, 0, sizeof(DRBG));
	}
	if (seed_material_in != NULL) {
		HJCrypto_memset(seed_material_in, 0, seed_material_Len);
		free(seed_material_in);
	}
	HJCrypto_memset(seed_material , 0, sizeof(seed_material));
	return ret;
}

RET CTR_DRBG_Reseed(DRBG* info, uint8_t* entropy, uint32_t entropyLen, uint8_t* add_input, uint32_t addLen)
{
	uint8_t seed_meterial[MAX_SEEDLEN_IN_BYTES];
	uint8_t* seed_meterial_in = NULL;
	uint8_t* ptr = NULL;
	RET ret = FAILURE;
	uint32_t seed_meterial_Len = 0;
	uint32_t i = 0;
	uint32_t j = 0;

	if (addLen > info->seedLen)
		addLen = info->seedLen;
	if (info->derivation_func_flag == USE_DF) {
		HJCrypto_memset(seed_meterial, 0, MAX_SEEDLEN_IN_BYTES);
		seed_meterial_Len = entropyLen;
		if (addLen > 0)
			seed_meterial_Len += addLen;
		ptr = seed_meterial_in = (uint8_t*)malloc(seed_meterial_Len);
		memcpy(ptr, entropy, entropyLen);
		if (addLen > 0) {
			ptr += entropyLen;
			memcpy(ptr, add_input, addLen);
		}
		if (Blockcipher_df(info->func, info->keyLen, seed_meterial_in, seed_meterial_Len, seed_meterial, info->seedLen) != SUCCESS) {
			ret = FAILURE;
			goto EXIT;
		}
	}
	else {
		i = addLen <= entropyLen ? addLen : entropyLen;
		HJCrypto_memset(seed_meterial, 0, MAX_SEEDLEN_IN_BYTES);
		if (add_input == NULL || addLen == 0) {
			for (j = 0; j < entropyLen; j++)
				seed_meterial[j] = entropy[j];
		}
		else {
			for (j = 0; j < i; j++)
				seed_meterial[j] = entropy[j] ^ add_input[j];
		}
	}
	if (CTR_DRBG_update(seed_meterial, info) != SUCCESS) {
		ret = FAILURE;
		goto EXIT;
	}
	info->reseed_cnt = 1;
	HJCrypto_memset(seed_meterial, 0, sizeof(seed_meterial));
	HJCrypto_memset(ptr, 0, sizeof(ptr));
	seed_meterial_Len = 0;
	i = 0;
	j = 0;
	ptr = NULL;
	return SUCCESS;
EXIT:
	if (ret != SUCCESS) {
		HJCrypto_memset(info, 0, sizeof(DRBG));
	}
	if (seed_meterial_in != NULL) {
		HJCrypto_memset(seed_meterial_in, 0, seed_meterial_Len);
		free(seed_meterial_in);
	}
	HJCrypto_memset(seed_meterial, 0, sizeof(seed_meterial));
	i = 0;
	j = 0;
	ptr = NULL;
	return ret;
}

RET CTR_DRBG_Generate(DRBG* info, uint8_t* output, uint64_t request_bitLen, uint8_t* entropy, uint64_t entroyLen, uint8_t* add_input, uint32_t addLen, uint32_t prediction_resistance_flag)
{
	uint8_t additional_input_seed[MAX_SEEDLEN_IN_BYTES];
	int32_t request_Len = 0;
	RET ret = 0;
	uint8_t* temp = NULL;
	uint8_t* ptr = NULL;
	uint32_t tempLen = 0;

	if (addLen > info->seedLen)
		addLen = info->seedLen;
	request_Len = (request_bitLen >> 3) + ((request_bitLen % 8) != 0 ? 1 : 0);
	info->prediction_res_flag = prediction_resistance_flag;
	if ((info->prediction_res_flag == NO_PR) || (info->reseed_cnt >= MAX_RESSED_CTR_LEN)) {
		if ((add_input != NULL) && (addLen > 0)) {
			if (info->derivation_func_flag == USE_DF) {
				ret = Blockcipher_df(info->func, info->keyLen, add_input, addLen, additional_input_seed, info->seedLen);
				if (ret == FAILURE) {
					HJCrypto_memset(additional_input_seed, 0, MAX_SEEDLEN_IN_BYTES);
					goto EXIT;
				}
				ret = CTR_DRBG_update(additional_input_seed, info);
				if (ret == FAILURE) {
					HJCrypto_memset(additional_input_seed, 0, MAX_SEEDLEN_IN_BYTES);
					goto EXIT;
				}
			}
			else {
				HJCrypto_memset(additional_input_seed, 0, MAX_SEEDLEN_IN_BYTES);
				memcpy(additional_input_seed, add_input, addLen);
				ret = CTR_DRBG_update(additional_input_seed, info);
				if (ret == FAILURE) {
					HJCrypto_memset(additional_input_seed, 0, MAX_SEEDLEN_IN_BYTES);
					goto EXIT;
				}
			}
		}
		else
			HJCrypto_memset(additional_input_seed, 0, MAX_SEEDLEN_IN_BYTES);
	}
	else {
		//ret = HJ_CTR_DRBG_Reseed
		if (ret == FAILURE) {
			goto EXIT;
		}
		HJCrypto_memset(additional_input_seed, 0, MAX_SEEDLEN_IN_BYTES);
	}

	tempLen = request_Len + (MAX_V_LEN_IN_BYTES - (request_Len % MAX_V_LEN_IN_BYTES));
	temp = (uint8_t*)malloc(tempLen);
	ptr = temp;
	tempLen = 0;

	while (tempLen < request_Len) {
		ctr_increase(info->V);
		HJCrypto_BlockCipher(info->func, ECB, ENCRYPTION, info->key, info->keyLen, info->V, BLOCKSIZE, NULL, ptr);
		ptr += BLOCKSIZE;
		tempLen += BLOCKSIZE;
	}
	memcpy(output, temp, request_Len);
	if (request_bitLen % 8 != 0)
		output[request_Len - 1] = temp[request_Len - 1] & (0x000000FF & (0xFF << (8 - (request_bitLen % 8))));
	ret = CTR_DRBG_update(additional_input_seed, info);
	if (ret == FAILURE) {
		goto EXIT;
	}
	info->reseed_cnt++;
	HJCrypto_memset(additional_input_seed, 0, MAX_SEEDLEN_IN_BYTES);
	request_Len = 0;
	tempLen = 0;
	temp = NULL;
	ptr = NULL;
	return ret;
EXIT:
	if (ret != SUCCESS) {
		HJCrypto_memset(info, 0, sizeof(DRBG));
	}
	if (temp != NULL) {
		HJCrypto_memset(temp, 0, tempLen);
		free(temp);
	}
	HJCrypto_memset(additional_input_seed, 0, MAX_SEEDLEN_IN_BYTES);
	return ret;
}