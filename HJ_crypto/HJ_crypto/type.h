#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef bool RET;

#define IN
#define OUT

#define SUCCESS 1
#define FAILURE 0

//Src Function
RET HJCrypto_memset(void* pointer, uint32_t value, uint32_t size);

