#include "KAT_TEST.h"
#include "HJ_crypto.h"

static uint32_t str2hex(uint8_t* out, char* in) {
	uint32_t ret = 0;
	while (in[ret] != '\0') {
		out[ret] = in[ret];
		ret++;
	}
	return ret;
}

static unsigned char getHex(unsigned char ch)
{
	unsigned char hex = 0;
	if (ch >= '0' && ch <= '9')
		hex = ch - '0';
	else if (ch >= 'a' && ch <= 'f')
		hex = ch - 'a' + 10;
	else if (ch >= 'A' && ch <= 'F')
		hex = ch - 'A' + 10;
	return hex;
}

static uint32_t asci2hex(uint8_t* out, uint8_t* in) {
	uint32_t i = 0;
	uint32_t j = 0;
	uint32_t ch = 0;
	while (in[i] != 0x00) {
		ch = in[i];
		out[j] = getHex(ch);
		out[j] <<= 4;
		ch = in[i + 1];
		out[j] |= getHex(ch);
		i = i + 2;
		j = j + 1;
	}
	return j;
}

//blockCipher TestVector
typedef struct {
	uint32_t func;
	uint32_t mode;
	uint8_t key[32];
	uint32_t keyLen;
	uint8_t pt[256];
	uint32_t ptLen;
	uint8_t ct[512];
	uint32_t ctLen;
	uint8_t IV[16];
}blockCipher_TV;

static const blockCipher_TV test[] = {
	{LEA, ECB, {0x0A,0xFA,0x4D,0x21,0xAF,0x94,0x2D,0xB8,0x87,0x76,0x87,0xED,0x5D,0xD5,0x09,0xC8}, 16, 
	{0xEB,0x0E,0xEE,0xA7,0xE6,0x98,0x22,0xD5,0x3B,0x37,0xA6,0x5E,0x99,0x73,0x37,0x22,0x2F,0x49,0x2A,0x29,0xB7,0x20,0x9B,0x36,0xB3,0xFF,0xC6,0x9F,0xF6,0xFC,0xB5,0x5B}, 32, 
	{0x89,0xBC,0x18,0xFB,0x6F,0x22,0xA5,0x66,0x3A,0x3A,0x8C,0x91,0xB3,0x96,0x06,0x4E,0x6D,0xFD,0x45,0x01,0x55,0xCD,0x54,0x83,0xFD,0x62,0xA7,0xB0,0x26,0x3A,0x51,0xF8}, 32,
	{0x00}},
	{LEA, ECB, {0x4A,0x9A,0xA2,0x8C,0xF9,0xA5,0x7A,0x60,0xAE,0x38,0xEC,0xC7,0x85,0xCC,0x23,0x8F,0x26,0x3D,0x14,0x28,0x52,0x16,0xB4,0x06}, 24, 
	{0xBB,0x0F,0x69,0x47,0x19,0xD4,0xBF,0x96,0x7A,0x08,0x5D,0x4F,0xD9,0x8A,0x37,0xE3,0xF3,0xF7,0x05,0x7F,0x56,0x70,0xF3,0xE8,0xBB,0x9D,0x9A,0xAA,0x95,0xF1,0x2F,0x71}, 32,
	{0x25,0xEE,0x8F,0xBE,0x22,0xFC,0xEB,0x00,0xFC,0xB6,0x1A,0xB5,0x95,0x3E,0x4A,0xAD,0x59,0x47,0x3B,0xB3,0x49,0xD2,0x7D,0x0D,0xAF,0xD5,0xDD,0x1D,0x11,0x3A,0xE7,0x5F}, 32,
	{0x00}},
	{LEA, ECB, {0x70,0x62,0xEA,0xE7,0x25,0xFF,0x24,0x49,0x10,0x43,0x82,0xF2,0x0B,0xB9,0x32,0xEA,0x47,0xD5,0xA9,0x65,0x7B,0x88,0xE4,0xF5,0x41,0x12,0xF4,0xFF,0xBC,0x18,0xB9,0x6C}, 32,
	{0x7F,0xF6,0xEE,0xA0,0xAA,0x56,0x65,0xB0,0x56,0x02,0x94,0xCF,0x34,0xF6,0x51,0x0A,0x70,0xBA,0xDA,0x36,0xDC,0xEE,0x18,0x26,0x4A,0x26,0x25,0x21,0x39,0xF9,0x0B,0x92}, 32,
	{0x24,0x87,0xC5,0x99,0x7C,0xCA,0x03,0xC0,0x06,0x98,0xFE,0x7A,0x16,0x1B,0x81,0x94,0x85,0x67,0xB5,0xE8,0xA5,0x50,0x49,0x78,0x1C,0x76,0xA7,0x1F,0xDA,0x77,0x00,0x8D}, 32,
	{0x00}},
	{LEA, CTR, {0xAE,0x38,0xEC,0xC7,0x85,0xCC,0x23,0x8F,0x26,0x3D,0x14,0x28,0x52,0x16,0xB4,0x06}, 16,
	{0xF3,0xF7,0x05,0x7F,0x56,0x70,0xF3,0xE8,0xBB,0x9D,0x9A,0xAA,0x95,0xF1,0x2F,0x71,0xEA,0x30,0xFA,0xB7,0x62,0x2F,0x0A,0x9F,0x9E,0xDC,0x28,0x21,0xCA,0x7D,0x09,0x68}, 32,
	{0x96,0x7C,0xEC,0xD0,0xC2,0xB8,0xD3,0x38,0xE9,0xB5,0xDD,0xFD,0x29,0x9D,0xC7,0x72,0x84,0xE4,0x6E,0xD6,0x8E,0xD0,0xC9,0x51,0x24,0x3A,0x9C,0x38,0x3D,0x6F,0x15,0xE9}, 32,
	{0xBB,0x0F,0x69,0x47,0x19,0xD4,0xBF,0x96,0x7A,0x08,0x5D,0x4F,0xD9,0x8A,0x37,0xE3}},
};

uint32_t blockCipher_SelfTest_API() {
	uint32_t ret = success;
	uint8_t ciphertext[512];
	uint8_t recovered[512];
	uint64_t outLen = 0;
	blockCipher info;
	int j = 0;
	for (uint32_t i = 0; i < sizeof(test) / sizeof(blockCipher_TV); i++) {
		HJCrypto_memset(ciphertext, 0, sizeof(ciphertext));
		HJCrypto_memset(recovered, 0, sizeof(recovered));
		//BlockCipher Function Test[ENCRYPTION]
		HJCrypto_BlockCipher(test[i].func, test[i].mode, ENCRYPTION, test[i].key, test[i].keyLen, test[i].pt, test[i].ptLen, test[i].IV, ciphertext);
		if (memcmp(test[i].ct, ciphertext, test[i].ptLen)) {
			ret = KAT_SELFTEST_FAILURE;
			goto EXIT;
		}

		//BlockCipher_init/process/final test
		HJCrypto_BlockCipher_init(test[i].func, test[i].mode, DECRYPTION, test[i].key, test[i].keyLen, test[i].IV);
		HJCrypto_BlockCipher_Update(ciphertext, test[i].ptLen, recovered, &outLen);
		HJCrypto_BlockCipher_final(recovered);
		if (memcmp(test[i].pt, recovered, test[i].ptLen)) {
			ret = KAT_SELFTEST_FAILURE;
			goto EXIT;
		}
	}
	HJCrypto_memset(ciphertext, 0, sizeof(ciphertext));
	HJCrypto_memset(recovered, 0, sizeof(recovered));
	HJCrypto_memset(&info, 0, sizeof(blockCipher));
	outLen = 0;
	return success;
EXIT:
	if (ret == KAT_SELFTEST_FAILURE) {
		fprintf(stdout, "[위치] : blockCipher_SelfTest_API()\n");
		fprintf(stdout, "[이유] : blockCipher_KAT_TEST ERROR\n");
		HJCrypto_memset(ciphertext, 0, sizeof(ciphertext));
		HJCrypto_memset(recovered, 0, sizeof(recovered));
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		outLen = 0;
	}
}

typedef struct {
	uint32_t func;
	uint8_t msg[512];
	uint8_t hash[256];
}Hash_TV;

static const Hash_TV hash_test[] = {
	{sha256,
	"abc",
	"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"},
	{sha256,
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"},
};

uint32_t Hash_SelfTest_API() {
	uint32_t ret = success;
	uint8_t hashDigest[SHA256_DIGEST_LEN];
	uint8_t msg[512];
	uint8_t testvector[SHA256_DIGEST_LEN];
	uint64_t msgLen = 0;
	uint64_t hashLen = 0;
	int32_t i = 0;
	for (i = 0; i < sizeof(hash_test) / sizeof(Hash_TV); i++) {
		HJCrypto_memset(hashDigest, 0, sizeof(hashDigest));
		HJCrypto_memset(msg, 0, sizeof(msg));
		HJCrypto_memset(testvector, 0, sizeof(testvector));

		msgLen = str2hex(msg, (char*)hash_test[i].msg);
		hashLen = asci2hex(testvector, hash_test[i].hash);
		HJCrypto_Hash(hash_test[i].func, msg, msgLen, hashDigest);

		if (memcmp(hashDigest, testvector, SHA256_DIGEST_LEN)) {
			ret = KAT_SELFTEST_FAILURE;
			goto EXIT;
		}
		HJCrypto_memset(hashDigest, 0, SHA256_DIGEST_LEN);

		HJCrypto_Hash_init(hash_test[i].func);
		HJCrypto_Hash_process(msg, msgLen);
		HJCrypto_Hash_final(hashDigest);
		if (memcmp(hashDigest, testvector, SHA256_DIGEST_LEN)) {
			ret = KAT_SELFTEST_FAILURE;
			goto EXIT;
		}
	}
	HJCrypto_memset(hashDigest, 0, sizeof(hashDigest));
	HJCrypto_memset(msg, 0, sizeof(msg));
	HJCrypto_memset(testvector, 0, sizeof(testvector));
	msgLen = 0;
	hashLen = 0;
	return ret;
EXIT:
	if (ret == KAT_SELFTEST_FAILURE) {
		fprintf(stdout, "[위치] : Hash_SelfTest_API()\n");
		fprintf(stdout, "[이유] : Hash_SelfTest_API ERROR\n");
		HJCrypto_memset(hashDigest, 0, sizeof(hashDigest));
		HJCrypto_memset(msg, 0, sizeof(msg));
		HJCrypto_memset(testvector, 0, sizeof(testvector));
		msgLen = 0;
		hashLen = 0;
		return ret;

	}
}

typedef struct {
	uint32_t func;
	uint8_t key[256];
	uint8_t msg[1024];
	uint8_t mac[256];
	uint64_t keyLen;
}HMAC_TV;

static const HMAC_TV hmac_test[] = {
	{
		HMAC_SHA256,
		"53B54FAFBB0020655734B45E8F63E2E01FA96886CB103A414DB1199C931C6644",
		"27FA39C7EFF1AE9C16C87F644ACCD86F28726682F43DB2D78EE2AD66A1AB8B631E19D508E9CDBA94D2A8A794C63217614638ABEA19BA7DB33E04B21E251A4EEA1F594CF9125CEF56711D53766B5C47BE63455F46A14D44DD475D4F4D863256E01104C622D265F2E9DD6DAB93A214118F66DFA81FF4BFAF5B8F36AD7A2CBB4C4D",
		"316CC8FA89B5BBBDC412005D8345ECC8FA22B2189A65BA66A26F62B4351FCF49",
		32
	},

	{
		HMAC_SHA256,
		"DED2BD1A5C79A507DE552B672C5D7C7C137EDE4A1284FB9D563E7C4DE9DDDAC1269E71B270A9D73123386BECCBFB31AD94BCDD23023F2DE5E26C7CB481AF95001BA0C5AE96DF341970427457F7335BBDB8530EA539645F6EEB6559C55AFE1823A71FDF9738E564C6AEBD6E3017CBA2B5658D9A5720BB384157723A09DC920E32",
		"B165E7F5BD811040C3EF8100958CB09C85B0A9C11D0E616510DB47066F331D3320B8064E8D7CE0909921D34DD83E2A7AFF05626C992381E2FCE8AA467CA8ED30DE61632C109D7BBD179A8FA248A9BB57BBD4EEDFFDC341C105E1885169BA2730D2A72816AEAE8ACF24A4DB844D94093CA16575A2AFB64909120D0CADA031733C",
		"EDFB8E12F79A1922965D7BAF256BF7E44F6794EDEBB98F36A0AE857CE5BBD1C0",
		128
	},


};

uint32_t HMAC_SelfTest_API() {
	uint32_t ret = success;
	uint8_t key[256];
	uint8_t msg[1024];
	uint8_t test_mac[HMAC_SHA256_DIGEST];
	uint8_t mac[HMAC_SHA256_DIGEST];

	uint32_t keyLen = 0;
	uint32_t msgLen = 0;
	uint32_t macLen = 0;
	uint32_t i = 0;
	for (i = 0; i < sizeof(hmac_test) / (sizeof(HMAC_TV)); i++) {
		HJCrypto_memset(key, 0, sizeof(key));
		HJCrypto_memset(msg, 0, sizeof(msg));
		HJCrypto_memset(test_mac, 0, sizeof(test_mac));
		HJCrypto_memset(mac, 0, sizeof(mac));

		keyLen = asci2hex(key, hmac_test[i].key);
		msgLen = asci2hex(msg, hmac_test[i].msg);
		macLen = asci2hex(test_mac, hmac_test[i].mac);
		HJCrypto_HMAC(hmac_test[i].func, key, hmac_test[i].keyLen, msg, msgLen, mac);
		if (memcmp(mac, test_mac, macLen)) {
			ret = KAT_SELFTEST_FAILURE;
			goto EXIT;
		}

		HJCrypto_memset(mac, 0, sizeof(mac));
		HJCrypto_HMAC_init(hmac_test[i].func, key, hmac_test[i].keyLen);
		HJCrypto_HMAC_process(msg, msgLen);
		HJCrypto_HMAC_final(mac);
		if (memcmp(mac, test_mac, macLen)) {
			ret = KAT_SELFTEST_FAILURE;
			goto EXIT;
		}
	}
	HJCrypto_memset(key, 0, sizeof(key));
	HJCrypto_memset(msg, 0, sizeof(msg));
	HJCrypto_memset(test_mac, 0, sizeof(test_mac));
	HJCrypto_memset(mac, 0, sizeof(mac));
	keyLen = 0;
	msgLen = 0;
	macLen = 0;
	return ret;
EXIT:
	if (ret == KAT_SELFTEST_FAILURE) {
		fprintf(stdout, "[위치] : HMAC_SelfTest_API()\n");
		fprintf(stdout, "[이유] : HMAC_SelfTest_API ERROR\n");
		HJCrypto_memset(key, 0, sizeof(key));
		HJCrypto_memset(msg, 0, sizeof(msg));
		HJCrypto_memset(test_mac, 0, sizeof(test_mac));
		HJCrypto_memset(mac, 0, sizeof(mac));
		keyLen = 0;
		msgLen = 0;
		macLen = 0;
		return ret;
	}
}

typedef struct {
	uint32_t func;
	uint32_t keyLen;
	uint32_t PR_flag;
	uint32_t DF_flag;
	uint32_t EntropyLen;
	uint32_t NonceLen;
	uint32_t perLen;
	uint32_t AddLen;
	uint32_t returnLen;
	uint8_t Entropy[512];
	uint8_t Nonce[512];
	uint8_t Per_string[512];
	uint8_t	EN_reseed[512];
	uint8_t AD_reseed[512];
	uint8_t AD_input1[512];
	uint8_t AD_input2[512];
	uint8_t RB[512];
}DRBG_TV;

//최종 API 호출
uint32_t HJCrypto_KAT_SELF_TEST() {
	uint32_t ret = success;
	ret = blockCipher_SelfTest_API();

}