#include "HJ_crypto.h"
#include "KAT_TEST.h"

FUNC_TEST func_test_state;
uint32_t HJCrypto_state = HJ_LOAD;

uint32_t _getState() {
	return HJCrypto_state;
}

static uint32_t _preSelf_test() {
	uint32_t ret = success;
	HJCrypto_memset(&func_test_state, 0, sizeof(FUNC_TEST));
	func_test_state.blockCipherTest = NOT_katselp_testing;
	func_test_state.HashTest = NOT_katselp_testing;
	func_test_state.HMACTest = NOT_katselp_testing;
	func_test_state.DRBGTest = NOT_katselp_testing;

	ret = _KAT_SELF_TEST();
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: _KAT_SELF_TEST		//\n");
		goto EXIT;
	}
EXIT:
	return ret;
}

void _Change_HJCrypto_state(uint32_t change) {
	switch (change)
	{
	case HJ_LOAD:
		HJCrypto_state = HJ_LOAD;
		break;
	case HJ_NORMAL:
		HJCrypto_state = HJ_NORMAL;
		break;
	case HJ_preSELF_test:
		HJCrypto_state = HJ_preSELF_test;
		break;
	case HJ_condition_test:
		HJCrypto_state = HJ_condition_test;
		break;
	case HJ_normal_err:
		HJCrypto_state = HJ_normal_err;
		break;
	case HJ_critical_err:
		HJCrypto_state = HJ_critical_err;
		break;
	case HJ_exit:
		HJCrypto_state = HJ_exit;
		break;
	default:
		break;
	}
}

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

uint32_t HJCrypto_getState() {
	uint32_t state = _getState();
	if (state == HJ_critical_err) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: HJ_critical_err		//\n");
		fprintf(stdout, "//		[*] : Reset HJCrypto_module			//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n");
	}
	return state;
}


void HJCrypto_Finish() {
	HJCrypto_memset(&func_test_state, 0, sizeof(FUNC_TEST));
	if (_getState() == HJ_critical_err) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] finish	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[*] state	: HJ_critical_err		//\n");
		fprintf(stdout, "//		[*] state	: Not normal state	[or]//\n");
		fprintf(stdout, "//		[*] state	: KAT Testing FAIL	[or]//\n");
		fprintf(stdout, "//		[*] state	: Entropy Test FAIL	[or]//\n");
		fprintf(stdout, "//		[*] state	: Integrity FAIL	[or]//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n");
	}
	else
	{
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] finish	: HJCrypto Version : 1.0//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n");
		_Change_HJCrypto_state(HJ_exit);
	}
	return;
}

uint32_t HJCrypto_preSelf_Test() {
	uint32_t ret = success;
	uint32_t state = _getState();

	if (state != HJ_LOAD) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//			[HJCrypto Version : 1.0]		//\n");
		fprintf(stdout, "//		[Location] : HJCrypto_preSelf_Test	//\n");
		fprintf(stdout, "//		[*] : Reset HJCrypto_module			//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n");

		ret = FAIL_invaild_state;
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//pretesting start
	fprintf(stdout, "/////////////////////////////////////////////\n");
	fprintf(stdout, "//			[HJCrypto Version : 1.0]		//\n");
	fprintf(stdout, "//		[Location]	: HJCrypto_preSelf_Test	//\n");
	fprintf(stdout, "//		[*] state	: HJ_preSELF_test		//\n");
	fprintf(stdout, "//		[*]			: preSELF_testing		//\n");
	_Change_HJCrypto_state(HJ_preSELF_test);
	ret = _preSelf_test();
	
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HJCrypto_preSelf_Test	//\n");
		fprintf(stdout, "//		[*] state	: FAIL preSelf_Test		//\n");
		fprintf(stdout, "//		[*] state	: HJ_critical_err		//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n");
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}
	fprintf(stdout, "//		[*] state	: success				//\n");
	fprintf(stdout, "//		[*] state	: HJ_NORMAL				//\n");
	fprintf(stdout, "/////////////////////////////////////////////\n");
	_Change_HJCrypto_state(HJ_NORMAL);

	return ret;
}

void HJCrypto_Info() {
	if (_getState() != HJ_NORMAL) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state	[or]//\n");
		fprintf(stdout, "//		[Location] : _getState				//\n");
		fprintf(stdout, "//		[*] : Reset HJCrypto_module			//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n");
		return;
	}
	fprintf(stdout, "/////////////////////////////////////////////\n");
	fprintf(stdout, "//			[HJCrypto Version : 1.0]		//\n");
	fprintf(stdout, "//		[*] Made by	: Hojin Choi			//\n");
	fprintf(stdout, "/////////////////////////////////////////////\n");
	return;
}

void HJCrypto_Load()
{
	uint32_t ret = success;
	_Change_HJCrypto_state(HJ_LOAD);
	_Change_HJCrypto_state(HJ_preSELF_test);
	fprintf(stdout, "/////////////////////////////////////////////\n");
	fprintf(stdout, "//		[*] state	: HJCrypto_Load success	//\n");
	fprintf(stdout, "//		[*] state	: HJCrypto_preSelf_Test //\n");
	fprintf(stdout, "//		[*] state	: _preSelf_Testing..... //\n");
	ret = _KAT_SELF_TEST();


	if (ret != success) {
		fprintf(stdout, "//		[Location] : HJCrypto_Load			//\n");
		fprintf(stdout, "//		[*] state	: HJ_critical_err		//\n");
		fprintf(stdout, "//		[*] state	: critical_err Detect	//\n");
		_Change_HJCrypto_state(HJ_critical_err);
		goto EXIT;
	}
	else {
		fprintf(stdout, "//		[*] state	: _preSelf_success		//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: HJCrypto_init			//\n");
		fprintf(stdout, "//////////////Support Algorithm//////////////\n");
		fprintf(stdout, "//		[BlockCipher] : LEA(ECB, CTR)		//\n");
		fprintf(stdout, "//		[Hash		] : SHA-256				//\n");
		fprintf(stdout, "//		[MAC		] : HMAC-SHA-256		//\n");
		fprintf(stdout, "//		[DRBG		] : CTR-DRBG(LEA)		//\n");
		fprintf(stdout, "//		[*] state	: HJ_NORMAL				//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n");
		_Change_HJCrypto_state(HJ_NORMAL);
	}
	return;
EXIT:
	HJCrypto_Finish();
}