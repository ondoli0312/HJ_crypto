#define _CRT_SECURE_NO_WARNINGS
#include "HMAC-SHA.h"
#include "integrity.h"
#include <assert.h>

#define fileName "HJ_Crypto.dylib"

//{ 0x78,0x47,0x12,0x77,0xA7,0xE8,0xE4,0x28,0x64,0x82,0xE8,0xE9,0xF7,0x8B,0xCB,0x89,0x82,0xEB,0xE2,0xD2,0x36,0x62,0x07,0x0E,0xC6,0x24,0xA4,0xCA,0x1C,0xC7,0x0D,0xD9,0x7A,0x94,0x4B,0xAB,0xB5,0x06,0xCB,0x8C,0x67,0x32,0xE1,0x04,0x24,0x16,0x55,0xCF,0x21,0x10,0x87,0x4F,0x26,0xFA,0x11,0x59,0x07,0xB0,0x2D,0x03,0xEC,0xA0,0x8E,0x31 };

uint8_t mask1[16] = { 0x96, 0x08, 0x33, 0xDF, 0x3E, 0x2E, 0xAB, 0xF8, 0xB0, 0xE1, 0xB5, 0xB2, 0x40, 0x38, 0xDD, 0xF5};
uint8_t mask2[16] = { 0x86, 0x78, 0x20, 0x5B, 0x04, 0x2D, 0xAF, 0xE4, 0x0A, 0x7A, 0xF0, 0xEB, 0xD7, 0xAE, 0xC6, 0x58};

uint8_t key3[16] = { 0x7B, 0x83, 0x59, 0xB3, 0xA2, 0x1D, 0xB1, 0x46, 0xE3, 0xB6, 0x88, 0xBF, 0x92, 0x0A, 0x03, 0xDA};
uint8_t key4[16] = { 0xA1, 0x6A, 0xCD, 0x1C, 0x9B, 0xE1, 0x8D, 0xA1, 0x30, 0x05, 0xD2, 0x82, 0x2B, 0x67, 0x4E, 0xA9};

uint32_t _integrity_test() {

	//file open
	uint32_t i = 0;
	uint32_t ret = success;
	uint8_t local_temp[64] = { 0, };
	uint8_t preMAC[HMAC_SHA256_DIGEST];
	uint8_t computeMAC[HMAC_SHA256_DIGEST];

	uint8_t key1[16] = { 0xEE, 0x4F, 0x21, 0xA8, 0x99, 0xC6, 0x4F, 0xD0, 0xD4, 0x63, 0x5D, 0x5B, 0xB7, 0xB3, 0x16, 0x7C };
	uint8_t key2[16] = { 0x04, 0x93, 0xC2, 0x89, 0x32, 0x4F, 0xA8, 0xEA, 0xCC, 0x5E, 0x54, 0x21, 0xCB, 0x69, 0xCB, 0x81 };
	uint8_t mask3[16] = { 0x01, 0x17, 0x12, 0x18, 0x17, 0x1B, 0x7A, 0xCA, 0x84, 0x84, 0x69, 0xBB, 0xB6, 0x1C, 0x56, 0x15 };
	uint8_t mask4[16] = { 0x80, 0x7A, 0x4A, 0x53, 0xBD, 0x1B, 0x9C, 0xF8, 0x37, 0xB5, 0xFF, 0x81, 0xC7, 0xC7, 0xC0, 0x98 };
	uint64_t fileLen = 0;
	int32_t readLen = 0;
	FILE* fp = NULL;
	uint8_t* buffer = NULL;
	MAC info;

	fp = fopen(fileName, "rb");
	assert(fp != NULL);
	fseek(fp, 0, SEEK_END);
	fileLen = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	buffer = (uint8_t*)malloc(fileLen);
	assert(buffer != NULL);
	
	HJCrypto_memset(buffer, 0, sizeof(fileLen));
	readLen = fread(buffer, sizeof(uint8_t), fileLen, fp);
	memcpy(preMAC, &buffer[fileLen - HMAC_SHA256_DIGEST], HMAC_SHA256_DIGEST);
	
	for (i = 0; i < 16; i++) {
		local_temp[i] = mask1[i] ^ key1[i];
		local_temp[i + 16] = mask2[i] ^ key2[i];
		local_temp[i + 32] = mask3[i] ^ key3[i];
		local_temp[i + 48] = mask4[i] ^ key4[i];
	}

	HJCrypto_HMAC(HMAC_SHA256, local_temp, sizeof(local_temp), buffer, fileLen - HMAC_SHA256_DIGEST, computeMAC);
	if (memcmp(computeMAC, preMAC, HMAC_SHA256_DIGEST)) {
		ret = FAIL_integrity_test;
		goto EXIT;
	}
	if (fp != NULL)
		fclose(fp);
	if (buffer != NULL) {
		HJCrypto_memset(buffer, 0, fileLen);
		free(buffer);

	}
	HJCrypto_memset(local_temp, 0, sizeof(local_temp));
	HJCrypto_memset(preMAC, 0, sizeof(preMAC));
	HJCrypto_memset(computeMAC, 0, sizeof(computeMAC));
	HJCrypto_memset(key1, 0, sizeof(key1));
	HJCrypto_memset(key2, 0, sizeof(key2));
	HJCrypto_memset(mask3, 0, sizeof(mask3));
	HJCrypto_memset(mask4, 0, sizeof(mask4));
	fileLen = 0;
	readLen = 0;
	return ret;
EXIT:
	if (fp != NULL)
		fclose(fp);
	if (buffer != NULL) {
		HJCrypto_memset(buffer, 0, fileLen);
		free(buffer);

	}
	HJCrypto_memset(local_temp, 0, sizeof(local_temp));
	HJCrypto_memset(preMAC, 0, sizeof(preMAC));
	HJCrypto_memset(computeMAC, 0, sizeof(computeMAC));
	HJCrypto_memset(key1, 0, sizeof(key1));
	HJCrypto_memset(key2, 0, sizeof(key2));
	HJCrypto_memset(mask3, 0, sizeof(mask3));
	HJCrypto_memset(mask4, 0, sizeof(mask4));
	fileLen = 0;
	readLen = 0;
	return ret;
}
	