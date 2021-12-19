#include "HJ_crypto.h"
#include "DRBG.h"
#include "HMAC-SHA.h"
#include "SHA-2 core.h"

void prints_hex(char* s, uint8_t* arr, uint32_t size) {
	printf("%s = ", s);
	for (int i = 0; i < size; i++)
		printf("%02X ", arr[i]);
	printf("\n");
}

static uint32_t HMAC_DRBG_update(
	HMAC_DRBG* info,
	uint8_t* provide_data,
	uint32_t pro_Len)
{
	uint32_t ret = success;
	int32_t i = 0;
	uint64_t size = info->DigestLen + 1 + pro_Len;
	uint8_t state_key[32];
	uint8_t state_V[32];
	uint8_t* state = (uint8_t*)calloc(size, sizeof(uint8_t));
	if (state == NULL)
		return;
	memcpy(state, info->V, info->DigestLen);
	state[info->DigestLen] = 0;
	memcpy(state + info->DigestLen + 1, provide_data, pro_Len);

	//Set Key
	HJCrypto_HMAC(info->func, info->key, info->DigestLen, state, size, state_key);
	memcpy((info->key), state_key, info->DigestLen);

	//Set V
	HJCrypto_HMAC(info->func, info->key, info->DigestLen, info->V, info->DigestLen, state_V);
	memcpy(info->V, state_V, info->DigestLen);


	if (pro_Len == 0) {
		i = 0;
		size = 0;
		HJCrypto_memset(state_key, 0, 32);
		HJCrypto_memset(state_V, 0, 32);
		HJCrypto_memset(state, 0, size);
		free(state);
		return ret;
	}
	else {

		state[info->DigestLen] = 0x01;
		memcpy(state, info->V, info->DigestLen);
		memcpy(state + info->DigestLen + 1, provide_data, pro_Len);

		//Set Key
		HJCrypto_HMAC(info->func, info->key, info->DigestLen, state, size, state_key);
		memcpy((info->key), state_key, info->DigestLen);

		//Set V
		HJCrypto_HMAC(info->func, info->key, info->DigestLen, info->V, info->DigestLen, state_V);
		memcpy(info->V, state_V, info->DigestLen);

		i = 0;
		size = 0;
		HJCrypto_memset(state_key, 0, 32);
		HJCrypto_memset(state_V, 0, 32);
		HJCrypto_memset(state, 0, size);
		free(state);
		return ret;
	}
}

uint32_t HMAC_DRBG_instantiate(
	HMAC_DRBG* info, uint32_t func,
	uint8_t* Entropy, uint32_t EntropyLen,
	uint8_t* Nonce, uint32_t NonceLen,
	uint8_t* per_s, uint32_t perLen,
	uint32_t PR_flag
)
{
	int32_t i = 0;
	uint32_t ret = success;
	uint32_t size = 0;
	uint8_t* seed_buffer = NULL;
	HJCrypto_memset(info, 0, sizeof(HMAC_DRBG));
	info->func = func;
	info->EntropyLen = EntropyLen;
	info->NonceLen = NonceLen;
	info->PerLen = perLen;
	info->PR_flag = PR_flag;
	info->DigestLen = SHA256_DIGEST_LEN;
	
	size = info->EntropyLen + info->NonceLen + info->PerLen;
	seed_buffer = (uint8_t*)calloc(size, sizeof(uint8_t));
	if (seed_buffer == NULL) {
		return;
	}

	memcpy(seed_buffer, Entropy, info->EntropyLen);
	memcpy(seed_buffer + info->EntropyLen, Nonce, info->NonceLen);
	memcpy(seed_buffer + info->EntropyLen + info->NonceLen, per_s, info->PerLen);

	for (i = 0; i < info->DigestLen; i++) {
		info->key[i] = 0x00;
		info->V[i] = 0x01;
	}

	HMAC_DRBG_update(info, seed_buffer, size);

	info->reseed_counter = 1;
	i = 0;
	size = 0;
	HJCrypto_memset(seed_buffer, 0, size);
	free(seed_buffer);
	return ret;
}

uint32_t HMAC_DRBG_reseed(
	HMAC_DRBG* info,
	uint8_t* Entropy,	uint32_t EntropyLen,
	uint8_t* add,		uint32_t addLen
)
{
	uint32_t ret = success;
	uint32_t size = EntropyLen + addLen;
	info->EntropyLen = EntropyLen;
	info->addLen = addLen;
	
	uint8_t* seed_material = (uint8_t*)calloc(size, sizeof(uint8_t));
	if (seed_material == NULL)
		return;

	memcpy(seed_material, Entropy, info->EntropyLen);
	memcpy(seed_material + info->EntropyLen, add, addLen);

	ret = HMAC_DRBG_update(info, seed_material, size);

	if (ret != success)
		goto EXIT;
	info->reseed_counter = 1;
	HJCrypto_memset(seed_material, 0, size);
	free(seed_material);
	size = 0;
	return ret;

EXIT:
	HJCrypto_memset(seed_material, 0, size);
	free(seed_material);
	size = 0;
	ret = FAIL_critical;
	return ret;
}

uint32_t HMAC_DRBG_Generate(
	HMAC_DRBG* info, 
	uint8_t* out,		uint32_t outLen,
	uint8_t* Entropy,	uint8_t* EntropyLen,
	uint8_t* add,		uint8_t* addLen,
	uint32_t PR_flag
)
{
	uint32_t ret = success;
	uint32_t remain = 0;
	uint32_t out_index = 0;
	
	uint8_t* v_temp = (uint8_t*)calloc(info->DigestLen, sizeof(uint8_t));
	if (v_temp == NULL)
		goto EXIT;

	info->PR_flag = PR_flag;
	info->EntropyLen = EntropyLen;
	info->addLen = addLen;
	if (info->reseed_counter > MAX_REESED_CTR_LEN || info->PR_flag == USE_PR) {
		ret = HMAC_DRBG_reseed(info, Entropy, info->EntropyLen, add, info->addLen);
		if (ret != success) {
			ret = FAIL_inner_func;
			goto EXIT;
		}
		info->addLen = 0;
	}
	if (info->addLen != 0) {
		printf("È£Ãâ\n");
		ret = HMAC_DRBG_update(info, add, addLen);
		if (ret != success) {
			ret = FAIL_inner_func;
			goto EXIT;
		}
	}
	remain = outLen / info->DigestLen;
	for (int32_t i = 0; i < remain; i++) {
		ret = HJCrypto_HMAC(info->func, info->key, info->DigestLen, info->V, info->DigestLen, v_temp);
		if (ret != success) {
			ret = FAIL_inner_func;
			goto EXIT;
		}
		memcpy(info->V, v_temp, (info->DigestLen));
		memcpy(out + out_index, v_temp, info->DigestLen);
		HJCrypto_memset(v_temp, 0, info->DigestLen);
		out_index += info->DigestLen;
	}
	remain = outLen % info->DigestLen;
	if (remain > 0) {
		ret = HJCrypto_HMAC(info->func, info->key, info->DigestLen, info->V, info->DigestLen, v_temp);
		if (ret != success) {
			ret = FAIL_inner_func;
			goto EXIT;
		}
		memcpy(info->V, v_temp, sizeof(info->DigestLen));
		memcpy(out + out_index, v_temp, remain);
		out_index += remain;
	}
	ret = HMAC_DRBG_update(info, add, info->addLen);
	if (ret != success) {
		ret = FAIL_inner_func;
		goto EXIT;
	}
	info->reseed_counter += 1;
	return ret;
EXIT:
	if (ret != success)
	{
		return ret;
	}
}