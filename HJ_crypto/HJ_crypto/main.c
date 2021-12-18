#include "HJ_crypto.h"

int main()
{
	blockCipher_SelfTest_API();
	Hash_SelfTest_API();
	HMAC_SelfTest_API();
	return 0;
}