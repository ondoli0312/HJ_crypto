#include "HJ_crypto.h"

uint32_t HJCrypto_memset(void* pointer, uint32_t value, uint32_t size)
{
    uint32_t ret = success;
    if (pointer == NULL)
    {
        return success;
    }

    volatile uint8_t* vp = (volatile uint8_t*)pointer;
    while (size)
    {
        *vp = value;
        vp++;
        size--;
    }
    return success;
}

