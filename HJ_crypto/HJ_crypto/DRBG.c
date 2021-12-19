#include "HJ_crypto.h"
#include "DRBG.h"

static HMAC_DRBG info;
extern FUNC_TEST func_test_state;
extern uint32_t HJCrypto_state;
extern uint32_t _getState();
extern void _Change_HJCrypto_state(uint32_t change);

__declspec(dllexport) uint32_t HJCrypto_HMAC_DRBG_Instantiate(
	uint32_t func, 
	uint8_t* Entropy,		uint32_t EntropyLen,
	uint8_t* Nonce,			uint32_t NonceLen,
	uint8_t* per_s,			uint32_t PerLen,
	uint32_t PR_flag
)
{
	uint32_t ret = success;
	uint32_t p_flag = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	:HMAC_DRBG_Instantiate	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.DRBGTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//	[Location]	: HJCrypto_HMAC_DRBG_Instantiate//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));

	if (func != HMAC_SHA256) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((PR_flag != USE_PR) && (PR_flag != NO_PR)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (((Nonce == NULL) && (NonceLen != 0))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (((per_s == NULL) && (PerLen != 0)) || (PerLen > (MAX_PER_STRING_LEN >> 3)) ) {
		p_flag = FAIL_PERS_LEN_MAX;
		goto PERR;
	}
	if (EntropyLen == 0) {
		uint8_t getEntropy[MAX_ENTROPY_LEN];
		_Change_HJCrypto_state(HJ_Entropy_test);
		ret = _DRBG_using(getEntropy, MAX_ENTROPY_LEN, 0);
		if (ret != success) {
			HJCrypto_memset(getEntropy, 0, MAX_ENTROPY_LEN);
			goto EXIT;
		}
		_Change_HJCrypto_state(HJ_NORMAL);
		ret = HMAC_DRBG_instantiate(&info, func, getEntropy, MAX_ENTROPY_LEN, Nonce, NonceLen, per_s, PerLen, PR_flag);
		if (ret != success) {
			HJCrypto_memset(getEntropy, 0, MAX_ENTROPY_LEN);
			goto EXIT;
		}
		HJCrypto_memset(getEntropy, 0, MAX_ENTROPY_LEN);
	}
	else {
		ret = HMAC_DRBG_instantiate(&info, func, Entropy, EntropyLen, Nonce, NonceLen, per_s, PerLen, PR_flag);
		if (ret != success)
			goto EXIT;
	}
	return ret;
PERR:
	_Change_HJCrypto_state(HJ_normal_err);
	fprintf(stdout, "/////////////////////////////////////////////\n");
	fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter[or]//\n");
	fprintf(stdout, "//		[*] state	: FAIL_PERS_LEN_MAX		//\n");
	fprintf(stdout, "//		[Location]	: HMAC_DRBG_Instantiate	//\n");
	fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
	fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
	fprintf(stdout, "/////////////////////////////////////////////\n\n");
	_Change_HJCrypto_state(HJ_NORMAL);
	HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));
	return p_flag;
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC			//\n");
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));
		HJCrypto_Finish();
	}
}

__declspec(dllexport) uint32_t HJCrypto_HMAC_DRBG_Reseed(
	uint8_t* Entropy, uint32_t EntropyLen,
	uint8_t* add, uint32_t addLen
)
{
	uint32_t ret = success;
	uint32_t p_flag = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	:HMAC_DRBG_Reseed		//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.DRBGTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	:HMAC_DRBG_Reseed		//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if (((add == NULL) && (addLen != 0)) || (addLen > (MAX_ADD_INPUT_LEN >> 3))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	if (((Entropy == NULL) && (EntropyLen != 0)) || (EntropyLen > MAX_ENTROPY_LEN)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (EntropyLen == 0) {
		uint8_t getEntropy[MAX_ENTROPY_LEN];
		_Change_HJCrypto_state(HJ_Entropy_test);
		ret = _DRBG_using(getEntropy, MAX_ENTROPY_LEN, 0);
		if (ret != success) {
			HJCrypto_memset(getEntropy, 0, MAX_ENTROPY_LEN);
			goto EXIT;
		}
		_Change_HJCrypto_state(HJ_NORMAL);
		ret = HMAC_DRBG_reseed(&info, getEntropy, MAX_ENTROPY_LEN, add, addLen);
		if (ret != success) {
			HJCrypto_memset(getEntropy, 0, MAX_ENTROPY_LEN);
			goto EXIT;
		}
		HJCrypto_memset(getEntropy, 0, MAX_ENTROPY_LEN);
	}
	else {
		ret = HMAC_DRBG_reseed(&info, Entropy, EntropyLen, add, addLen);
		if (ret != success)
			goto EXIT;
	}
	return ret;

PERR:
	_Change_HJCrypto_state(HJ_normal_err);
	fprintf(stdout, "/////////////////////////////////////////////\n");
	fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter[or]//\n");
	fprintf(stdout, "//		[*] state	: MAX_ADD_INPUT_LEN		//\n");
	fprintf(stdout, "//		[Location]	: HMAC_DRBG_Reseed		//\n");
	fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
	fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
	fprintf(stdout, "/////////////////////////////////////////////\n\n");
	_Change_HJCrypto_state(HJ_NORMAL);
	HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));
	return p_flag;
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HMAC_DRBG_Reseed		//\n");
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));
		HJCrypto_Finish();
	}
}

__declspec(dllexport) uint32_t HJCrypto_HMAC_DRBG_Generate(
	uint8_t* out, uint32_t outLen,
	uint8_t* Entropy, uint8_t* EntropyLen,
	uint8_t* add, uint8_t* addLen,
	uint32_t PR_flag
)
{
	uint32_t ret = success;
	uint32_t p_flag = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HMAC_DRBG_Generate	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.DRBGTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	:HMAC_DRBG_Reseed		//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((out == NULL) && (outLen != 0)) {
		p_flag = FAIL_invaild_paramter;
		
		goto PERR;
		
	}

	if (PR_flag != USE_PR && PR_flag != NO_PR) {
		p_flag = FAIL_invaild_paramter;
	
		goto PERR;
		
	}
	if (((add == NULL) && (addLen != 0)) || (addLen > (MAX_ADD_INPUT_LEN >> 3))) {
		p_flag = FAIL_invaild_paramter;
		
		goto PERR;
	}

	if (((Entropy == NULL) && (EntropyLen != 0)) || (EntropyLen > MAX_ENTROPY_LEN)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	if (EntropyLen == 0) {
		uint8_t getEntropy[MAX_ENTROPY_LEN];
		_Change_HJCrypto_state(HJ_Entropy_test);
		ret = _DRBG_using(getEntropy, MAX_ENTROPY_LEN, 0);
		if (ret != success) {
			HJCrypto_memset(getEntropy, 0, MAX_ENTROPY_LEN);
			goto EXIT;
		}
		_Change_HJCrypto_state(HJ_NORMAL);
		ret = HMAC_DRBG_Generate(&info, out, outLen, getEntropy, MAX_ENTROPY_LEN, add, addLen, PR_flag);
		if (ret != success) {
			HJCrypto_memset(getEntropy, 0, MAX_ENTROPY_LEN);
			goto EXIT;
		}
		HJCrypto_memset(getEntropy, 0, MAX_ENTROPY_LEN);
	}
	else {
		ret = HMAC_DRBG_Generate(&info, out, outLen, Entropy, EntropyLen, add, addLen, PR_flag);
		if (ret != success) {
			goto EXIT;
		}
	}
	return ret;
PERR:
	_Change_HJCrypto_state(HJ_normal_err);
	fprintf(stdout, "/////////////////////////////////////////////\n");
	fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter[or]//\n");
	fprintf(stdout, "//		[Location]	: HJ_HMAC_DRBG_Generate	//\n");
	fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
	fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
	fprintf(stdout, "/////////////////////////////////////////////\n\n");
	_Change_HJCrypto_state(HJ_NORMAL);
	HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));
	return p_flag;
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HMAC_DRBG_Generate	//\n");
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_memset(&info, 0, sizeof(HMAC_DRBG));
		HJCrypto_Finish();
	}
}