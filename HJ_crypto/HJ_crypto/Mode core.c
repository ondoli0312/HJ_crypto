#include "mode core.h"
#include "type.h"


/*
typedef struct {
	uint32_t ptLen;
	uint32_t keyLen;
	uint32_t ENC; //알고리즘(LEA
	uint32_t MODE;
	uint32_t TYPE;
	uint8_t IV[BLOCKSIZE];
	uint8_t lastBlock[BLOCKSIZE];
	LEA_KEY* LEA_key;
	ARIA_KEY* ARIA_key;
}blockCipher;
*/

//최종 제공 API
//aria
//aria init
//aria process
//aria final
//aria clear


RET HJ_crypto_ARIA() {
	//init -> 구조체에 파라미터 설정
	//process -> 실제 암호화
	//final -> 마지막 블록 암호화 및 파라미터 제로화
}


RET CTR_ADD(uint8_t* ctr)
{
	int i = 0;
	uint8_t carry = 0;
	uint8_t temp = 0;
	for (i = 15; i >= 0; i--) {
		temp = ctr[i] + carry;
		if (temp < ctr[i])
			carry = 1;
		else
			carry = 0;
		ctr[i] = temp;
	}
}

RET ARIA_ENC_CBC(blockCipher* info, uint8_t* pt, uint64_t ptLen, uint8_t* ct, uint64_t* ctLen) {
	uint64_t i, j;
	uint8_t IV[16];
	uint8_t ct_temp[16];
	RET ret = FAILURE;
	memcpy(IV, info->IV, BLOCKSIZE);
	for (i = 0; i < ptLen / BLOCKSIZE; i++) {
		for (j = 0; j < 16; j++) {
			IV[j] = *(pt + (i * BLOCKSIZE)) ^ IV[j];
		}
		ARIA_encryption(IV, &(info->ARIA_key), ct_temp);
		memcpy(IV, ct_temp, BLOCKSIZE);
		memcpy(ct + (i * BLOCKSIZE), ct_temp, BLOCKSIZE);
		info->encrypted_len += BLOCKSIZE;
		*(ctLen) = *(ctLen)+BLOCKSIZE;
	}
	j = ptLen % BLOCKSIZE;
	memcpy(info->IV, IV, BLOCKSIZE);
	memcpy(info->lastBlock, pt + (i * BLOCKSIZE), j);
	ret = HJCrypto_memset(IV, 0, BLOCKSIZE);
	ret = HJCrypto_memset(ct_temp, 0, BLOCKSIZE);
	i = 0;
	j = 0;
	return ret;
}

RET ARIA_DEC_CBC(blockCipher* info, uint8_t* pt, uint64_t ptLen, uint8_t* ct, uint64_t* ctLen) {
	uint64_t i, j;
	uint8_t IV[16];
	uint8_t ct_temp[16];
	RET ret = FAILURE;
	memcpy(IV, info->IV, BLOCKSIZE);
	for (i = 0; i < ptLen / BLOCKSIZE; i++) {
		for (j = 0; j < 16; j++) {
			IV[j] = *(pt + (i * BLOCKSIZE)) ^ IV[j];
		}
		ARIA_encryption(IV, &(info->ARIA_key), ct_temp);
		memcpy(IV, ct_temp, BLOCKSIZE);
		memcpy(ct + (i * BLOCKSIZE), ct_temp, BLOCKSIZE);
		info->encrypted_len += BLOCKSIZE;
		*(ctLen) = *(ctLen)+BLOCKSIZE;
	}
	j = ptLen % BLOCKSIZE;
	memcpy(info->IV, IV, BLOCKSIZE);
	memcpy(info->lastBlock, pt + (i * BLOCKSIZE), j);
	ret = HJCrypto_memset(IV, 0, BLOCKSIZE);
	ret = HJCrypto_memset(ct_temp, 0, BLOCKSIZE);
	i = 0;
	j = 0;
	return ret;
}


RET ARIA_CTR(blockCipher* info, uint8_t* pt, uint64_t ptLen, uint8_t* ct, uint64_t* ctLen) {
	uint64_t i, j;
	uint8_t IV[16];
	uint8_t ct_temp[16];
	RET ret = FAILURE;
	memcpy(IV, info->IV, BLOCKSIZE);
	for (i = 0; i < ptLen / BLOCKSIZE; i++) {
		ARIA_encryption(IV, &(info->ARIA_key), ct_temp);
		for (j = 0; j < 16; j++)
			ct_temp[j] = *(pt + (i * BLOCKSIZE)) ^ IV[j];
		memcpy(ct + (i * BLOCKSIZE), ct_temp, BLOCKSIZE);
		ret = CTR_ADD(IV);
	}
	j = ptLen % BLOCKSIZE;
	memcpy(info->IV, IV, BLOCKSIZE);
	memcpy(info->lastBlock, pt + (i * BLOCKSIZE), j);
	ret = HJCrypto_memset(IV, 0, BLOCKSIZE);
	ret = HJCrypto_memset(ct_temp, 0, BLOCKSIZE);
	i = 0;
	j = 0;
	return ret;
}

RET LEA_ENC_CBC(blockCipher* info, uint8_t* pt, uint64_t ptLen, uint8_t* ct, uint64_t* ctLen)
{
	uint64_t i, j;
	uint8_t IV[16];
	uint8_t ct_temp[16];
	RET ret = FAILURE;
	memcpy(IV, info->IV, BLOCKSIZE);
	for (i = 0; i < ptLen / BLOCKSIZE; i++) {
		for (j = 0; j < 16; j++) {
			IV[j] = *(pt + (i * BLOCKSIZE)) ^ IV[j];
		}
		LEA_encryption(IV, &(info->LEA_key), ct_temp);
		memcpy(IV, ct_temp, BLOCKSIZE);
		memcpy(ct + (i * BLOCKSIZE), ct_temp, BLOCKSIZE);
		info->encrypted_len += BLOCKSIZE;
		*(ctLen) = *(ctLen)+BLOCKSIZE;
	}
	j = ptLen % BLOCKSIZE;
	memcpy(info->IV, IV, BLOCKSIZE);
	memcpy(info->lastBlock, pt + (i * BLOCKSIZE), j);
	ret = HJCrypto_memset(IV, 0, BLOCKSIZE);
	ret = HJCrypto_memset(ct_temp, 0, BLOCKSIZE);
	i = 0;
	j = 0;
	return ret;
}

RET LEA_CTR(blockCipher* info, uint8_t* pt, uint64_t ptLen, uint8_t* ct, uint64_t* ctLen) {
	uint64_t i, j;
	uint8_t IV[16];
	uint8_t ct_temp[16];
	RET ret = FAILURE;
	memcpy(IV, info->IV, BLOCKSIZE);
	for (i = 0; i < ptLen / BLOCKSIZE; i++) {
		LEA_encryption(IV, &(info->LEA_key), ct_temp);
		for (j = 0; j < 16; j++)
			ct_temp[j] = *(pt + (i * BLOCKSIZE)) ^ IV[j];
		memcpy(ct + (i * BLOCKSIZE), ct_temp, BLOCKSIZE);
		ret = CTR_ADD(IV);
	}
	j = ptLen % BLOCKSIZE;
	memcpy(info->IV, IV, BLOCKSIZE);
	memcpy(info->lastBlock, pt + (i * BLOCKSIZE), j);
	ret = HJCrypto_memset(IV, 0, BLOCKSIZE);
	ret = HJCrypto_memset(ct_temp, 0, BLOCKSIZE);
	i = 0;
	j = 0;
	return ret;
}

//update
//final

RET ARIA_init(uint8_t* masterkey, uint32_t keyLen, uint32_t mode, uint32_t type, uint8_t* iv, blockCipher* info) {
	RET ret = FAILURE;
	info->ENC = ARIA;
	info->TYPE = type;
	info->MODE = mode;
	info->encrypted_len = 0;
	info->keyLen = keyLen;
	memcpy(info->IV, iv, BLOCKSIZE);
	if (masterkey == NULL)
		return ret;

	if (type == ENCRYPTION) {
		ret = ARIA_EncKeySetup(masterkey,  keyLen << 8, &(info->ARIA_key));
	}
	else if (type == DECRYPTION) {
		ret = ARIA_DecKeySetup(masterkey, keyLen << 8, &(info->ARIA_key));
	}
	else
		return FAILURE;
}





