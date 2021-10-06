#pragma once
#include "type.h"

//SHA-256 operation
#define SF(x, n)				(x >> n)
#define ROTL32(x, n)			(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n)			(((x) >> (n)) | ((x) << (32 - (n))))
#define ENDIAN_CHANGE32(X)		((ROTL((X),  8) & 0x00ff00ff) | (ROTL((X), 24) & 0xff00ff00))
#define CH(x, y, z)				((x & y) ^ (~(x) & (z)))
#define Maj(x, y, z)			(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define WE0(x)				(ROTR32(x,  7) ^ ROTR32(x, 18) ^ SF(x, 3))
#define WE1(x)				(ROTR32(x,  17) ^ ROTR32(x, 19) ^ SF(x, 10))

#define BS0(x)				((ROTR32(x,  2)) ^ ROTR32(x, 13) ^ ROTR32(x,  22))
#define BS1(x)				(ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x,  25))

#define SHA256_BLOCKBYTE	64

typedef struct {
	uint32_t hash[8];
	uint64_t	ptLen;
	uint8_t	BUF[SHA256_BLOCKBYTE];
}SHA256_INFO;

