#pragma once
#include "HJ_Crypto.h"

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

//SHA256-API/////////////////////////////////////////////////////////////////////////////////////////////
RET SHA256_init(IN Hash* info);
RET SHA256_process(IN const uint8_t* pt, IN uint64_t ptLen, IN Hash* info);
RET SHA256_final(IN Hash* info, OUT uint8_t* out);


