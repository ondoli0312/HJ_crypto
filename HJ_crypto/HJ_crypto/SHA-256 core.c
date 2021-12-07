#include "SHA-2 core.h"

static const uint32_t cont[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


RET SHA256_init(IN SHA256_INFO* info) {
	RET ret = FAILURE;
	if (info == NULL)
		return ret;
	info->hash[0] = 0x6a09e667;
	info->hash[1] = 0xbb67ae85;
	info->hash[2] = 0x3c6ef372;
	info->hash[3] = 0xa54ff53a;
	info->hash[4] = 0x510e527f;
	info->hash[5] = 0x9b05688c;
	info->hash[6] = 0x1f83d9ab;
	info->hash[7] = 0x5be0cd19;
	info->ptLen = 0;
	ret = HJCrypto_memset((uint8_t*)info->BUF, 0, SHA256_BLOCKBYTE);
	return ret;
}

static RET SHA256_BLOCK(IN const uint32_t* pt, IN SHA256_INFO* info) {
	RET ret = FAILURE;
	uint32_t W[64];
	uint32_t a = info->hash[0];
	uint32_t b = info->hash[1];
	uint32_t c = info->hash[2];
	uint32_t d = info->hash[3];
	uint32_t e = info->hash[4];
	uint32_t f = info->hash[5];
	uint32_t g = info->hash[6];
	uint32_t h = info->hash[7];
	uint32_t temp0 = 0;
	uint32_t temp1 = 0;

	for (int i = 0; i < 16; i++)
		W[i] = ENDIAN_CHANGE32(pt[i]);

	for (int i = 16; i < 64; i++) 
		W[i] = W[i - 16] + W[i - 7] + WE0(W[i - 15]) + WE1(W[i - 2]);

	for (int i = 0; i < 64; i++) {
		temp0 = h + BS1(e) + CH(e, f, g) + cont[i] + W[i];
		temp1 = (BS0(a)) + (Maj(a, b, c));
		h = g;
		g = f;
		f = e;
		e = d + temp0;
		d = c;
		c = b;
		b = a;
		a = temp0 + temp1;
	}

	info->hash[0] += a;
	info->hash[1] += b;
	info->hash[2] += c;
	info->hash[3] += d;
	info->hash[4] += e;
	info->hash[5] += f;
	info->hash[6] += g;
	info->hash[7] += h;

	//Data reset
	a = 0;
	b = 0;
	c = 0;
	d = 0;
	e = 0;
	f = 0;
	g = 0;
	h = 0;
	temp0 = 0;
	temp1 = 0;
	HJCrypto_memset(W, 0, sizeof(W));
	ret = SUCCESS;
	return ret;
}

RET SHA256_process(IN const uint8_t* pt, IN uint64_t ptLen, IN SHA256_INFO* info)
{
	RET ret = FAILURE;
	info->ptLen += ptLen;
	while (ptLen >= SHA256_BLOCKBYTE) {
		memcpy((uint8_t*)info->BUF, pt, SHA256_BLOCKBYTE);
		ret = SHA256_BLOCK((uint32_t*)info->BUF, info);
		if (ret == FAILURE)
			return FAILURE;
		pt += SHA256_BLOCKBYTE;
		ptLen -= SHA256_BLOCKBYTE;
	}
	memcpy((uint8_t*)info->BUF, pt, ptLen);
	return ret;
}

RET SHA256_final(IN SHA256_INFO* info, OUT uint8_t* out) {
	uint32_t r = (info->ptLen) % SHA256_BLOCKBYTE;
	RET ret = FAILURE;

	info->BUF[r++] = 0x80;
	if (r >= SHA256_BLOCKBYTE - 8) {
		HJCrypto_memset((uint8_t*)info->BUF + r, 0, SHA256_BLOCKBYTE - r);
		ret = SHA256_BLOCK((uint32_t*)info->BUF, info);
		if (ret == FAILURE)
			return FAILURE;
		HJCrypto_memset((uint8_t*)info->BUF, 0, SHA256_BLOCKBYTE - 8);
	}
	else {
		HJCrypto_memset((uint8_t*)info->BUF, 0, SHA256_BLOCKBYTE - 8 - r);
	}
	((uint32_t*)info->BUF)[SHA256_BLOCKBYTE / 4 - 2] = ENDIAN_CHANGE32((info->ptLen) >> 29);
	((uint32_t*)info->BUF)[SHA256_BLOCKBYTE / 4 - 1] = ENDIAN_CHANGE32((info->ptLen) << 3) & 0xffffffff;
	ret = SHA256_BLOCK((uint32_t*)info->BUF, info);
	if (ret == FAILURE)
		return FAILURE;

	out[0] = (info->hash[0] >> 24) & 0xff;
	out[1] = (info->hash[0] >> 16) & 0xff;
	out[2] = (info->hash[0] >> 8) & 0xff;
	out[3] = (info->hash[0]) & 0xff;

	out[4] = (info->hash[1] >> 24) & 0xff;
	out[5] = (info->hash[1] >> 16) & 0xff;
	out[6] = (info->hash[1] >> 8) & 0xff;
	out[7] = (info->hash[1]) & 0xff;

	out[8] = (info->hash[2] >> 24) & 0xff;
	out[9] = (info->hash[2] >> 16) & 0xff;
	out[10] = (info->hash[2] >> 8) & 0xff;
	out[11] = (info->hash[2]) & 0xff;

	out[12] = (info->hash[3] >> 24) & 0xff;
	out[13] = (info->hash[3] >> 16) & 0xff;
	out[14] = (info->hash[3] >> 8) & 0xff;
	out[15] = (info->hash[3]) & 0xff;

	out[16] = (info->hash[4] >> 24) & 0xff;
	out[17] = (info->hash[4] >> 16) & 0xff;
	out[18] = (info->hash[4] >> 8) & 0xff;
	out[19] = (info->hash[4]) & 0xff;

	out[20] = (info->hash[5] >> 24) & 0xff;
	out[21] = (info->hash[5] >> 16) & 0xff;
	out[22] = (info->hash[5] >> 8) & 0xff;
	out[23] = (info->hash[5]) & 0xff;

	out[24] = (info->hash[6] >> 24) & 0xff;
	out[25] = (info->hash[6] >> 16) & 0xff;
	out[26] = (info->hash[6] >> 8) & 0xff;
	out[27] = (info->hash[6]) & 0xff;

	out[28] = (info->hash[7] >> 24) & 0xff;
	out[29] = (info->hash[7] >> 16) & 0xff;
	out[30] = (info->hash[7] >> 8) & 0xff;
	out[31] = (info->hash[7]) & 0xff;

	//Memory set
	HJCrypto_memset((uint8_t*)info->BUF, 0, SHA256_BLOCKBYTE);
	HJCrypto_memset((uint8_t*)info->hash, 0, sizeof(uint32_t) * 8);
	info->ptLen = 0;
	r = 0;
	ret = SUCCESS;
	return ret;
}
