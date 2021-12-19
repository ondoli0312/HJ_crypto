#include "SHA-2 core.h"
#include "HJ_crypto.h"

Hash info;
extern FUNC_TEST func_test_state;
extern uint32_t HJCrypto_state;
extern uint32_t _getState();
extern void _Change_HJCrypto_state(uint32_t change);

__declspec(dllexport) uint32_t HJCrypto_Hash(uint32_t Func, const uint8_t* pt, uint64_t ptLen, uint8_t* Digest) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash			//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash			//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//Parameter Check
	if (Func != sha256) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((ptLen != 0) && (pt == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if (Digest == NULL){
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	ret = SHA256_init(&info);
	if (ret != success) {
		goto EXIT;
	}
	ret = SHA256_process(pt, ptLen, &info);
	if (ret != success) {
		goto EXIT;
	}
	ret = SHA256_final(&info, Digest);
	if (ret != success) {
		goto EXIT;
	}

	return ret;

PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash			//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash			//\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}

__declspec(dllexport) uint32_t HJCrypto_Hash_init(uint32_t Func) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//Parameter Check
	if (Func != sha256) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	ret = SHA256_init(&info);
	if (ret != success)
		goto EXIT;
	return ret;
PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_init	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_init	//\n");
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}

uint32_t HJCrypto_Hash_process(const uint8_t* pt, uint64_t ptLen) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_process	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}
	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_process	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//Parameter Check
	if ((ptLen != 0) && (pt == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	ret = SHA256_process(pt, ptLen, &info);
	if (ret != success)
		goto EXIT;

	return ret;
PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_process	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_process	//\n");
		ret = FAIL_critical;
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}

__declspec(dllexport) uint32_t HJCrypto_Hash_final(uint8_t* Digest) {
	uint32_t p_flag = success;
	uint32_t ret = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_final	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}
	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_final	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//Parameter Check
	if (Digest == NULL) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	ret = SHA256_final(&info, Digest);
	if (ret != success)
		goto EXIT;

	return ret;
PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_final	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		p_flag = 0;
		fprintf(stdout, "//		[Location]	: HJCrypto_Hash_final	//\n");
		ret = FAIL_critical;
		HJCrypto_memset(&info, 0, sizeof(Hash));
		return ret;
	}
}