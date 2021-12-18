#include "mode core.h"

static RET blockCipher_Clear(blockCipher* info) {
	RET ret = FAILURE;
	ret = HJCrypto_memset(info, 0, sizeof(blockCipher));
	return ret;
}

static RET CTR_ADD(uint8_t* ctr)
{
	int i = 0;
	uint8_t carry = 1;
	uint8_t temp = 0;
	for (i = 15; i >= 0; i--) {
		temp = ctr[i] + carry;
		if (temp < ctr[i])
			carry = 1;
		else
			carry = 0;
		ctr[i] = temp;
	};
}
//
//RET LEA_CTR(blockCipher* info, uint8_t* pt, uint64_t ptLen, uint8_t* ct, uint64_t* ctLen) {
//	uint64_t i, j;
//	uint8_t IV[16];
//	uint8_t ct_temp[16];
//	RET ret = FAILURE;
//	memcpy(IV, info->IV, BLOCKSIZE);
//	for (i = 0; i < ptLen / BLOCKSIZE; i++) {
//		LEA_encryption(IV, &(info->LEA_key), ct_temp);
//		for (j = 0; j < 16; j++)
//			ct_temp[j] = *(pt + (i * BLOCKSIZE)) ^ IV[j];
//		memcpy(ct + (i * BLOCKSIZE), ct_temp, BLOCKSIZE);
//		ret = CTR_ADD(IV);
//	}
//	j = ptLen % BLOCKSIZE;
//	memcpy(info->IV, IV, BLOCKSIZE);
//	memcpy(info->lastBlock, pt + (i * BLOCKSIZE), j);
//	ret = HJCrypto_memset(IV, 0, BLOCKSIZE);
//	ret = HJCrypto_memset(ct_temp, 0, BLOCKSIZE);
//	i = 0;
//	j = 0;
//	return ret;
//}

RET ECB_init(blockCipher* info, uint32_t Enc, const uint8_t* masterkey, uint32_t keyLen, uint32_t mode, uint32_t type) {
	RET ret = FAILURE;
	memset(info, 0, sizeof(blockCipher));
	if (Enc == LEA) {
		info->ENC = LEA;
		info->TYPE = type;
		info->MODE = ECB;
		info->encrypted_len = 0;
		info->keyLen = keyLen;
		if (info->TYPE == ENCRYPTION || info->TYPE == DECRYPTION) {
			ret = LEA_roundkeyGen(&(info->LEA_key), masterkey, keyLen);
		}
		else
			return FAILURE;
	}
	else
		return FAILURE;
	ret = SUCCESS;
	return ret;
}

RET CTR_init(blockCipher* info, uint32_t Enc, const uint8_t* masterkey, uint32_t keyLen, uint32_t mode, uint32_t type, const uint8_t* iv) {
	RET ret = FAILURE;
	memset(info, 0, sizeof(blockCipher));
	if (Enc == LEA) {
		info->ENC = LEA;
		info->TYPE = type;
		info->MODE = CTR;
		info->encrypted_len = 0;
		info->keyLen = keyLen;
		memcpy(info->IV, iv, BLOCKSIZE);
		if (info->TYPE == ENCRYPTION || info->TYPE == DECRYPTION) {
			ret = LEA_roundkeyGen(&(info->LEA_key), masterkey, keyLen);
		}
		else
			return FAILURE;
	}
	else
		return FAILURE;
	ret = SUCCESS;
	return ret;
}

RET ECB_update(blockCipher* info, const uint8_t* plaintext, uint64_t ptLen, uint8_t* out, uint64_t* outLen) {
	RET ret = FAILURE;
	uint32_t Encryption_Len = ptLen + (info->remain_Len);
	uint32_t pt_index = 0;
	uint8_t temp[BLOCKSIZE] = { 0, };
	uint8_t ct[BLOCKSIZE] = { 0, };
	memcpy(temp, info->lastBlock, info->remain_Len);
	while (Encryption_Len >= BLOCKSIZE) {
		//Remain Data 贸府秦林绰 何盒
		memcpy(temp + info->remain_Len, plaintext + pt_index, BLOCKSIZE);
		if ((info->ENC == LEA) && (info->TYPE == ENCRYPTION)) {
			LEA_encryption(temp, &(info->LEA_key), ct);
		}
		else if ((info->ENC == LEA) && (info->TYPE == DECRYPTION)) {
			LEA_decryption(ct, &(info->LEA_key), temp);
		}
		else {
			return FAILURE;
		}
		for (uint32_t i = 0; i < BLOCKSIZE; i++) {
			out[info->encrypted_len + i] = ct[i];
		}
		pt_index += (BLOCKSIZE - info->remain_Len);
		Encryption_Len -= (BLOCKSIZE - info->remain_Len);
		info->encrypted_len += (BLOCKSIZE - info->remain_Len);
		info->remain_Len = 0;
		*outLen += BLOCKSIZE;
	}
	memcpy(info->lastBlock, plaintext + pt_index, Encryption_Len);
	info->remain_Len = Encryption_Len;
	pt_index = 0;
	Encryption_Len = 0;
	ret = HJCrypto_memset(ct, 0, BLOCKSIZE);
	ret = HJCrypto_memset(temp, 0, BLOCKSIZE);
	return ret;
}

RET CTR_update(blockCipher* info, const uint8_t* plaintext, uint64_t ptLen, uint8_t* out, uint64_t* outLen) {
	RET ret = FAILURE;
	uint32_t Encryption_Len = ptLen + (info->remain_Len);
	uint32_t pt_index = 0;
	uint8_t ct[BLOCKSIZE] = { 0, };
	uint8_t IV[BLOCKSIZE] = { 0, };
	uint8_t temp[BLOCKSIZE] = { 0, };
	memcpy(temp, info->lastBlock, info->remain_Len);
	memcpy(IV, info->IV, BLOCKSIZE);
	while (Encryption_Len >= BLOCKSIZE) {
		//Remain Data 贸府秦林绰 何盒
		memcpy(temp + info->remain_Len, plaintext + pt_index, BLOCKSIZE);
		if (info->ENC == LEA) {
			LEA_encryption(IV, &(info->LEA_key), ct);
		}
		for (uint32_t i = 0; i < BLOCKSIZE; i++) {
			out[info->encrypted_len + i] = ct[i] ^ temp[i];
		}
		pt_index += (BLOCKSIZE - info->remain_Len);
		Encryption_Len -= (BLOCKSIZE - info->remain_Len);
		info->encrypted_len += (BLOCKSIZE - info->remain_Len);
		info->remain_Len = 0;
		*outLen += BLOCKSIZE;
		CTR_ADD(IV);
	}
	memcpy(info->IV, IV, BLOCKSIZE);
	memcpy(info->lastBlock, plaintext + pt_index, Encryption_Len);
	info->remain_Len = Encryption_Len;
	pt_index = 0;
	Encryption_Len = 0;
	ret = HJCrypto_memset(ct, 0, BLOCKSIZE);
	ret = HJCrypto_memset(IV, 0, BLOCKSIZE);
	ret = HJCrypto_memset(temp, 0, BLOCKSIZE);
	return ret;
}

RET ECB_final(blockCipher* info, uint8_t* out) {
	RET ret = FAILURE;
	uint8_t ct[BLOCKSIZE] = { 0, };
	uint8_t temp[BLOCKSIZE] = { 0, };
	if (info->remain_Len != 0) {
		memcpy(temp, info->lastBlock, info->remain_Len);
		if ((info->ENC == LEA) && (info->TYPE == ENCRYPTION)) {
			LEA_encryption(temp, &(info->LEA_key), ct);
		}
		else if ((info->ENC == LEA) && (info->TYPE == DECRYPTION)) {
			LEA_decryption(ct, &(info->LEA_key), temp);
		}
		else {
			return FAILURE;
		}
		for (uint32_t i = 0; i < info->remain_Len; i++) {
			out[info->encrypted_len + i] = ct[i];
		}
	}
	ret = HJCrypto_memset(ct, 0, BLOCKSIZE);
	ret = HJCrypto_memset(temp, 0, BLOCKSIZE);
	ret = blockCipher_Clear(info);
	return ret;
}

RET CTR_final(blockCipher* info, uint8_t* out) {
	RET ret = FAILURE;
	uint8_t ct[BLOCKSIZE] = { 0, };
	uint8_t IV[BLOCKSIZE] = { 0, };
	uint8_t temp[BLOCKSIZE] = { 0, };
	if (info->remain_Len != 0) {
		memcpy(temp, info->lastBlock, info->remain_Len);
		memcpy(IV, info->IV, BLOCKSIZE);
		if (info->ENC == LEA) {
			LEA_encryption(IV, &(info->LEA_key), ct);
		}
		for (uint32_t i = 0; i < info->remain_Len; i++) {
			out[info->encrypted_len + i] = ct[i] ^ temp[i];
		}
	}
	ret = HJCrypto_memset(ct, 0, BLOCKSIZE);
	ret = HJCrypto_memset(IV, 0, BLOCKSIZE);
	ret = HJCrypto_memset(temp, 0, BLOCKSIZE);
	ret = blockCipher_Clear(info);
	return ret;
}