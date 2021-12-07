#include "SHA-2 core.h"

static const uint64_t cont[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

RET SHA512_init(SHA512_INFO* info) {
	RET ret = FAILURE;
	if (info == NULL)
		return ret;
	info->hash[0] = 0x6a09e667f3bcc908;
	info->hash[1] = 0xbb67ae8584caa73b;
	info->hash[2] = 0x3c6ef372fe94f82b;
	info->hash[3] = 0xa54ff53a5f1d36f1;
	info->hash[4] = 0x510e527fade682d1;
	info->hash[5] = 0x9b05688c2b3e6c1f;
	info->hash[6] = 0x1f83d9abfb41bd6b;
	info->hash[7] = 0x5be0cd19137e2179;
	info->ptLen = 0;
	ret = HJCrypto_memset((uint8_t*)info->BUF, 0, SHA512_BLOCKBYTE);
	return ret;
}

static RET SHA512_BLOCK(IN const uint64_t* pt, OUT SHA512_INFO* info) 
{
	RET ret = FAILURE;
	uint64_t a = info->hash[0];
	uint64_t b = info->hash[1];
	uint64_t c = info->hash[2];
	uint64_t d = info->hash[3];
	uint64_t e = info->hash[4];
	uint64_t f = info->hash[5];
	uint64_t g = info->hash[6];
	uint64_t h = info->hash[7];
	uint64_t w0_t = pt[0];
	uint64_t w1_t = pt[0];
	uint64_t w2_t = pt[0];
	uint64_t w3_t = pt[0];
	uint64_t w4_t = pt[0];
	uint64_t w5_t = pt[0];
	uint64_t w6_t = pt[0];
	uint64_t w7_t = pt[0];
	uint64_t w8_t = pt[0];
	uint64_t w9_t = pt[0];
	uint64_t wa_t = pt[0];
	uint64_t wb_t = pt[0];
	uint64_t wc_t = pt[0];
	uint64_t wd_t = pt[0];
	uint64_t we_t = pt[0];
	uint64_t wf_t = pt[0];

#define ROUND_EXPAND()									\
{														\
		w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t);  \
		w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
		w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
		w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
		w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
		w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t);  \
		w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
		w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
		w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
		w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
		wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
		wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
		wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
		wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t);  \
		we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t);  \
		wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
}
#define ROUND_STEP(i)																	\
{																						\
		SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, cont[i +  0]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, cont[i +  1]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, cont[i +  2]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a ,b, c, d, e, w3_t, cont[i +  3]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a ,b, c, d, w4_t, cont[i +  4]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a ,b, c, w5_t, cont[i +  5]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, cont[i +  6]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, cont[i +  7]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, cont[i +  8]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, cont[i +  9]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, cont[i + 10]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a ,b, c, d, e, wb_t, cont[i + 11]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a ,b, c, d, wc_t, cont[i + 12]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a ,b, c, wd_t, cont[i + 13]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, cont[i + 14]);	\
		SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, cont[i + 15]);	\
}

	ROUND_STEP(0);
	for (int i = 16; i < 80; i += 16) {
		ROUND_EXPAND();
		ROUND_STEP(i);
	}
	info->hash[0] += a;
	info->hash[1] += b;
	info->hash[2] += c;
	info->hash[3] += d;
	info->hash[4] += e;
	info->hash[5] += f;
	info->hash[6] += g;
	info->hash[7] += h;
	a = 0; b = 0; c = 0; d = 0; e = 0; f = 0; g = 0; h = 0;
	w0_t = 0; w1_t = 0; w2_t = 0; w3_t = 0; w4_t = 0; w5_t = 0;
	w6_t = 0; w7_t = 0; w8_t = 0; w9_t = 0; wa_t = 0; wb_t = 0;
	wc_t = 0; wd_t = 0; we_t = 0; wf_t = 0;
	ret = SUCCESS;
	return ret;
}

RET SHA512_process(IN const uint8_t* pt, IN uint64_t ptLen, IN SHA512_INFO* info)
{
	RET ret = FAILURE;
	info->ptLen += ptLen;
	while (ptLen >= SHA512_BLOCKBYTE) {
		memcpy((uint8_t*)info->BUF, pt, SHA512_BLOCKBYTE);
		ret = SHA512_BLOCK((uint64_t*)info->BUF, info);
		if (ret == FAILURE)
			return FAILURE;
		pt += SHA512_BLOCKBYTE;
		ptLen -= SHA512_BLOCKBYTE;
	}
	memcpy((uint8_t*)info->BUF, pt, ptLen);
	ret = SUCCESS;
	return ret;
}

RET SHA512_final(IN SHA512_INFO* info, OUT uint8_t* out)
{
	uint64_t r = 0;
	RET ret = FAILURE;
	r = info->ptLen % 128;
	info->BUF[r++] = 0x80;
	if (r >= SHA512_BLOCKBYTE - 16) {
		HJCrypto_memset((uint8_t*)info->BUF + r, 0, SHA512_BLOCKBYTE - r);
		ret = SHA512_BLOCK((uint64_t*)info->BUF, info);
		if (ret == FAILURE)
			return FAILURE;
		HJCrypto_memset((uint8_t*)info->BUF, 0, SHA512_BLOCKBYTE - 16);
	}
	else {
		HJCrypto_memset((uint8_t*)info->BUF, 0, SHA512_BLOCKBYTE - 8 - r);
	}
	((uint64_t*)info->BUF)[14] = ENDIAN_CHANGE64(((info->ptLen) >> 61));
	((uint64_t*)info->BUF)[15] = (ENDIAN_CHANGE64(((info->ptLen) << 3))) & 0xffffffffffffffff;
	ret = SHA512_BLOCK((uint64_t*)info->BUF, info);
	if (ret == FAILURE)
		return FAILURE;
	for (int i = 0; i < 8; i++)
		*(uint64_t*)(out + (i << 3)) = ENDIAN_CHANGE64(info->hash[i]);
	HJCrypto_memset((uint8_t*)info->BUF, 0, SHA512_BLOCKBYTE);
	HJCrypto_memset((uint8_t*)info->hash, 0, sizeof(uint64_t) * 8);
	info->ptLen = 0;
	r = 0;
	ret = SUCCESS;
	return ret;
}

RET SHA512_claer(IN SHA512_INFO* info) {
	HJCrypto_memset((info), 0, sizeof(SHA512_INFO));
	return SUCCESS;
}