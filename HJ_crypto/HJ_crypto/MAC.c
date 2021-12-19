#include "HJ_crypto.h"
#include "HMAC-SHA.h"

static MAC info;
extern FUNC_TEST func_test_state;
extern uint32_t HJCrypto_state;
extern uint32_t _getState();
extern void _Change_HJCrypto_state(uint32_t change);

__declspec(dllexport) uint32_t HJCrypto_HMAC(uint32_t func, const uint8_t* key, uint64_t keyLen, const uint8_t* pt, uint64_t ptLen, uint8_t* out){
	uint32_t p_flag = success;
	uint32_t ret = success;
	uint32_t state = _getState();
	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC			//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.HMACTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC			//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}
	//Parameter Check
	if (func != HMAC_SHA256) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((key == NULL) || (pt == NULL) || (out == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((keyLen == 0) || (ptLen == 0) ) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//Processing
	ret = HMAC_init(&info, func, key, keyLen);
	if (ret != success) {
		goto EXIT;
	}
	ret = HMAC_process(&info, pt, ptLen);
	if (ret != success) {
		goto EXIT;
	}
	ret = HMAC_final(&info, out);
	if (ret != success) {
		goto EXIT;
	}
	return ret;
PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC			//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC			//\n");
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return ret;
	}
}

__declspec(dllexport) uint32_t HJCrypto_HMAC_init(uint32_t func, const uint8_t* key, uint64_t keyLen) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	uint32_t state = _getState();
	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//Parameter Check
	if (func != HMAC_SHA256) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((key == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((keyLen == 0)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//Processing
	ret = HMAC_init(&info, func, key, keyLen);
	if (ret != success) {
		goto EXIT;
	}

PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_init	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_init	//\n");
		ret = ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return ret;
	}
}

__declspec(dllexport) uint32_t HJCrypto_HMAC_process(const uint8_t* pt, uint64_t ptLen) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	uint32_t state = _getState();
	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_process	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_process	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//Parameter Check
	if ((pt == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((ptLen == 0)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//Processing
	ret = HMAC_process(&info, pt, ptLen);
	if (ret != success) {
		goto EXIT;
	}

PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_process	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_process	//\n");
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return ret;
	}
}

__declspec(dllexport) uint32_t HJCrypto_HMAC_final(uint8_t* out) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	uint32_t state = _getState();
	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_final	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_final	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//Parameter Check
	if ((out == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//Processing
	ret = HMAC_final(&info, out);
	if (ret != success) {
		goto EXIT;
	}

PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_process	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_final	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HJCrypto_HMAC_final	//\n");
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(MAC));
		return ret;
	}
}