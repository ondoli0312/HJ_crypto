#include "HJ_crypto.h"

int main()
{

	HJCrypto_Load();
	//LEA_CTR_MMT();
	//uint8_t entropy[256];
	//_DRBG_using(entropy, 256, 0);
	//HMAC_DRBG_SelfTest_API();
	//LEA_CTR_MCT();
	//LEA_CTR_KAT();
	//LEA_CTR_MMT();
	HMAC_DBBG_CAVP();
	return 0;
}