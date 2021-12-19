#include "Entropy.h"
#include <assert.h>

uint32_t APT_offset = 0;
uint32_t RCT_offset = 0;

static uint32_t _Adaptive_Test(uint8_t* Entrophy, uint32_t* addLen, uint8_t* in, uint32_t inLen)
{
    uint32_t ret = success;
    uint8_t temp[WINDOW_ENTROPY_LEN];

    if (*addLen == 0) {
        memcpy(Entrophy, in, inLen);
        *addLen += inLen;
    }
    else
    {
        memcpy(temp, Entrophy, WINDOW_ENTROPY_LEN);
        if (!memcmp(temp, in, inLen)) {
            APT_offset += 1;
            if (APT_offset == APT_OFF) {
                ret = FAIL_entropy_test;
                fprintf(stdout, "//	[Location]	: _Adaptive_Test	//\n");
                goto EXIT;
            }
            else
            {
                memcpy(Entrophy + *addLen, in, inLen);
                *addLen += inLen;
            }
            memcpy(Entrophy + *addLen, in, inLen);
            *addLen += inLen;
        }
        else
        {
            memcpy(Entrophy + *addLen, in, inLen);
            *addLen += inLen;
        }
    }
    HJCrypto_memset(temp, 0x00, sizeof(temp));
    return ret;
EXIT:
    if (ret != success) {
        HJCrypto_memset(temp, 0x00, sizeof(temp));
        return ret;
    }
}

static uint32_t _Repetition_Test(uint8_t* Entropy) {
    uint32_t ret = success;
    uint32_t f[WINDOW_ENTROPY_LEN];
    uint32_t s[WINDOW_ENTROPY_LEN];
    HCRYPTPROV   prov;
    HJCrypto_memset(f, 0x00, sizeof(f));
    HJCrypto_memset(s, 0x00, sizeof(s));

#ifdef _WIN64
    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        ret = FAIL_entropy_test;
        goto EXIT;
    }
    if (CryptGenRandom(prov, WINDOW_ENTROPY_LEN, f) == 0) {
        ret = FAIL_entropy_test;
        goto EXIT;
    }
    if (CryptGenRandom(prov, WINDOW_ENTROPY_LEN, s) == 0) {
        ret = FAIL_entropy_test;
        goto EXIT;
    }
#endif
    if (!memcmp(f, s, WINDOW_ENTROPY_LEN))
    {
        RCT_offset += 1;
        if (RCT_offset == RCT_OFF)
        {
            ret = FAIL_entropy_test;
            goto EXIT;
        }
    }
    else
    {
        memcpy(Entropy, s, WINDOW_ENTROPY_LEN);
    }


    if (prov)
    {
        if (!CryptReleaseContext(prov, 0))
        {
            ret = FAIL_entropy_test;
            goto EXIT;
        }
    }
    HJCrypto_memset(f, 0x00, sizeof(f));
    HJCrypto_memset(s, 0x00, sizeof(s));
EXIT:
    if (ret != success) {
        fprintf(stdout, "//	[Location]	: _Repetition_Test	//\n");
        HJCrypto_memset(f, 0x00, sizeof(f));
        HJCrypto_memset(s, 0x00, sizeof(s));
        ret = CriticalError;
        return ret;
    }
}

static uint32_t _genEntropy(uint8_t* Entropy, uint32_t Len) {
    uint32_t ret = success;
    uint32_t outLen = 0;
    uint32_t i = 0;
    uint32_t entropy_temp[MAX_ENTROPY_LEN];
    uint32_t temp[WINDOW_ENTROPY_LEN];

    HJCrypto_memset(entropy_temp, 0x00, MAX_ENTROPY_LEN);
    HJCrypto_memset(temp, 0x00, WINDOW_ENTROPY_LEN);

    for (i = 0; i < MAX_ENTROPY_LEN / WINDOW_ENTROPY_LEN; i++) {
        ret = _Repetition_Test(temp);
        if (ret != success)
            goto EXIT;
        ret = _Adaptive_Test(entropy_temp, &outLen, temp, WINDOW_ENTROPY_LEN);
        if (ret != success)
            goto EXIT;
    }
    memcpy(Entropy, entropy_temp, Len);
    HJCrypto_memset(entropy_temp, 0x00, MAX_ENTROPY_LEN);
    HJCrypto_memset(temp, 0x00, WINDOW_ENTROPY_LEN);
    outLen = 0;
    i = 0;
    return ret;
EXIT:
    if (ret != success) {
        fprintf(stdout, "//	[Location]	: _genEntropy	//\n");
        HJCrypto_memset(entropy_temp, 0x00, MAX_ENTROPY_LEN);
        HJCrypto_memset(temp, 0x00, WINDOW_ENTROPY_LEN);
        outLen = 0;
        i = 0;
    }
}
uint32_t _DRBG_using(uint8_t* Entropy, uint32_t inLen, uint32_t flag) {
    uint32_t ret = success;
    uint8_t* f = NULL;
    uint8_t* s = NULL;

    f = (uint8_t*)calloc(MAX_ENTROPY_LEN, sizeof(uint8_t));
    assert(f != NULL);
    s = (uint8_t*)calloc(MAX_ENTROPY_LEN, sizeof(uint8_t));
    assert(s != NULL);

    ret = _genEntropy(f, MAX_ENTROPY_LEN);
    if (ret != success)
        goto EXIT;
    ret = _genEntropy(s, MAX_ENTROPY_LEN);
    if (ret != success)
        goto EXIT;

    if (!(memcmp(f, s, MAX_ENTROPY_LEN))){
        ret = FAIL_entropy_test;
        goto EXIT;
    }
    if (!flag) {
        memcpy(Entropy, s, inLen);
    }
    HJCrypto_memset(f, 0, MAX_ENTROPY_LEN);
    HJCrypto_memset(s, 0, MAX_ENTROPY_LEN);
    free(f);
    free(s);
    return ret;
EXIT:
    if (ret != success) {
        ret = CriticalError;
        HJCrypto_memset(f, 0, MAX_ENTROPY_LEN);
        HJCrypto_memset(s, 0, MAX_ENTROPY_LEN);
        free(f);
        free(s);
        return ret;
    }

}
