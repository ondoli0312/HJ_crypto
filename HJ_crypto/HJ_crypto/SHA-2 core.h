#pragma once
#include "type.h"

//SHA-256 operation/////////////////////////////////////////////////////////////////////////////////////////////
#define SF(x, n)				(x >> n)
#define ROTL32(x, n)			(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n)			(((x) >> (n)) | ((x) << (32 - (n))))
#define ENDIAN_CHANGE32(X)		((ROTL32((X),  8) & 0x00ff00ff) | (ROTL32((X), 24) & 0xff00ff00))
#define CH(x, y, z)				((x & y) ^ (~(x) & (z)))
#define Maj(x, y, z)			(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define WE0(x)				(ROTR32(x,  7) ^ ROTR32(x, 18) ^ SF(x, 3))
#define WE1(x)				(ROTR32(x,  17) ^ ROTR32(x, 19) ^ SF(x, 10))
#define BS0(x)				((ROTR32(x,  2)) ^ ROTR32(x, 13) ^ ROTR32(x,  22))
#define BS1(x)				(ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x,  25))
#define SHA256_BLOCKBYTE	64
typedef struct {
	uint32_t hash[8];
	uint64_t ptLen;
	uint8_t	BUF[SHA256_BLOCKBYTE];
	uint32_t lastLen;
}SHA256_INFO;

//SHA256-API/////////////////////////////////////////////////////////////////////////////////////////////
RET SHA256_init(IN SHA256_INFO* info);
RET SHA256_process(IN const uint8_t* pt, IN uint64_t ptLen, IN SHA256_INFO* info);
RET SHA256_final(IN SHA256_INFO* info, OUT uint8_t* out);

//SHA-512 operation/////////////////////////////////////////////////////////////////////////////////////////////
#define ROTL64(x, n)			(((x) << (n)) | ((x) >> (64 - (n))))
#define ROTR64(x, n)			(((x) >> (n)) | ((x) << (64 - (n))))
//THETA
#define WE0_512(x)				(ROTR64(x,  1) ^ ROTR64(x, 8) ^ SF(x, 7))
#define WE1_512(x)				(ROTR64(x,  19) ^ ROTR64(x, 61) ^ SF(x, 6))
//SIGMA
#define BS0_512(x)				((ROTR64(x,  28)) ^ ROTR64(x, 34) ^ ROTR64(x,  39))
#define BS1_512(x)				(ROTR64(x,  14) ^ ROTR64(x, 18) ^ ROTR64(x,  41))
#define SHA512_F0(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define SHA512_F1(x,y,z) (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA512_BLOCKBYTE	128

//ENDIAN
#define ENDIAN_CHANGE64(val)	(\
(((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
(((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
(((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
(((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000))

//CORE OPERATION
#define SHA512_STEP(F0, F1, a, b, c ,d ,e ,f ,g ,h, x, K)	\
{															\
	h += K;													\
	h += x;													\
	h += BS1_512(e);										\
	h += F0(e, f, g);										\
	d += h;													\
	h += BS0_512(a);										\
	h += F1(a, b, c);										\
}

#define SHA512_EXPAND(x, y, z ,w) (WE1_512(x) + y + WE0_512(z) + w)

typedef struct {
	uint64_t hash[8];
	uint64_t ptLen;
	uint8_t	BUF[SHA512_BLOCKBYTE];
}SHA512_INFO;
//SHA512-API/////////////////////////////////////////////////////////////////////////////////////////////
RET SHA512_init(SHA512_INFO* info);
RET SHA512_process(IN const uint8_t* pt, IN uint64_t ptLen, IN SHA512_INFO* info);
RET SHA512_final(IN SHA512_INFO* info, OUT uint8_t* out);