#include "HMAC-SHA.h"
#include "HJ_crypto.h"
#include "SHA-2 core.h"

uint32_t HMAC_init(MAC* info, uint32_t func, const uint8_t* key, uint64_t keyLen)
{
	uint32_t ret = success;
	ret = HJCrypto_memset(info, 0, sizeof(MAC));
	switch (func)
	{
	case HMAC_SHA256 :
		info->func = func;
		//key 처리
		if (keyLen > HMAC_SHA256_BLOCKBYTE) {
			ret = SHA256_init(&(info->hash_info));
			ret = SHA256_process(key, keyLen, &(info->hash_info));
			ret = SHA256_final(&(info->hash_info), (info->key));
			info->keyLen = HMAC_SHA256_DIGEST;
			if (ret != success)
				return FAIL_inner_func;
			info->keyupdate_state = key_update_DONE;
		}
		else {
			//keyLen < HMAC_SHA256_BLOCKBYTE
			info->keyLen = keyLen;
			memcpy(info->key, key, keyLen);
			info->keyupdate_state = key_update_DONE;
		}
		break;
	default:
		return FAIL_inner_func;
	}
	return ret;
}

uint32_t HMAC_process(MAC* info, const uint8_t* pt, uint64_t ptLen) {
	
	//나중에 해시 함수 추가하면 해당 K1, K2 size 바꿔줘야 함
	uint8_t K1[HMAC_SHA256_BLOCKBYTE];
	switch (info->func)
	{
	case HMAC_SHA256:
		//update가 최초로 호출되어서 IPAD key에 대한 정보를 담아야하는 경우
		if (info->keyupdate_state == key_update_DONE) {
			memset(K1, 0x36, HMAC_SHA256_BLOCKBYTE);
			for (int i = 0; i < info->keyLen; i++)
				K1[i] = info->key[i] ^ K1[i];

			SHA256_init(&(info->hash_info));
			SHA256_process(K1, HMAC_SHA256_BLOCKBYTE, &(info->hash_info));
			SHA256_process(pt, ptLen, &(info->hash_info));
			info->keyupdate_state = key_update_DONE;
		}
		//update가 메시지 추가를 위한 여러번 호출되어서 IPAD key에 대한 정보가 이미 포함되어 있는 경우
		else {
			SHA256_process(pt, ptLen, &(info->hash_info));
		}
		break;
	default:
		return FAIL_inner_func;
		break;
	}
	uint32_t ret = HJCrypto_memset(K1, 0, HMAC_SHA256_BLOCKBYTE);
	return ret;
}

uint32_t HMAC_final(MAC* info, uint8_t* out) {
	//나중에 해시 함수 추가하면 해당 K1, K2 size 바꿔줘야 함
	uint8_t K2[HMAC_SHA256_BLOCKBYTE];
	uint8_t buf[HMAC_SHA256_DIGEST];
	uint32_t ret = success;
	switch (info->func)
	{
	case HMAC_SHA256:
		memset(K2, 0x5c, HMAC_SHA256_BLOCKBYTE);
		for (int i = 0; i < info->keyLen; i++)
			K2[i] = info->key[i] ^ K2[i];
		//IPAD + Message 생성
		SHA256_final(&(info->hash_info), buf);

		SHA256_init(&(info->hash_info));
		SHA256_process(K2, HMAC_SHA256_BLOCKBYTE, &(info->hash_info));
		SHA256_process(buf, HMAC_SHA256_DIGEST, &(info->hash_info));
		ret = SHA256_final(&(info->hash_info), out);
		break;
	default:
		return ret;
		break;
	}
	ret = HJCrypto_memset(K2, 0, HMAC_SHA256_BLOCKBYTE);
	ret = HJCrypto_memset(buf, 0, HMAC_SHA256_DIGEST);
	ret = HJCrypto_memset(info, 0, sizeof(MAC));
	return ret;
}