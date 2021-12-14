#include "HJ_crypto.h"

RET HJCrypto_memset(void* pointer, uint32_t value, uint32_t size)
{
    RET ret = FAILURE;
    if (pointer == NULL)
    {
        return SUCCESS;
    }

    volatile uint8_t* vp = (volatile uint8_t*)pointer;
    while (size)
    {
        *vp = value;
        vp++;
        size--;
    }
    return SUCCESS;
}

