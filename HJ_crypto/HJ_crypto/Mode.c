#include "HJ_crypto.h"
#include "mode core.h"

blockCipher info;
extern FUNC_TEST func_test_state;
extern uint32_t HJCrypto_state;
extern uint32_t _getState();
extern void _Change_HJCrypto_state(uint32_t change);

__declspec(dllexport) uint32_t HJCrypto_BlockCipher(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* in, uint64_t ptLen, const uint8_t* iv, uint8_t* out) {
	uint32_t ret = success;
	uint32_t p_flag = success;
	uint64_t outLen = 0;
	uint32_t state = _getState();
	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_BlockCipher	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_BlockCipher	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//parameter Check
	if ((Enc != LEA) || ((mode != CTR) && (mode != ECB)) ||((type != ENCRYPTION) && (type != DECRYPTION))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((masterkey == NULL) || ((keyLen != 16) && (keyLen != 24) && (keyLen != 32))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	//나중에 ECB 탑재하는 경우, iv가 NULL 일 수 있음.
	if ((in == NULL) || (out == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((mode == CTR) && (iv == NULL)) {
		if ((in == NULL) || (out == NULL)) {
			p_flag = FAIL_invaild_paramter;
			goto PERR;
		}
	}

	switch (mode)
	{
	case ECB:
		ret = ECB_init(&info, Enc, masterkey, keyLen, mode, type);
		if (ret != success)
			goto EXIT;
		ret = ECB_update(&info, in, ptLen, out, &outLen);
		if (ret != success)
			goto EXIT;
		ret = ECB_final(&info, out);
		if (ret != success)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_init(&info, Enc, masterkey, keyLen, mode, type, iv);
		if (ret != success)
			goto EXIT;
		ret = CTR_update(&info, in, ptLen, out, &outLen);
		if (ret != success)
			goto EXIT;
		ret = CTR_final(&info, out);
		if (ret != success)
			goto EXIT;
		break;
	default:
		goto EXIT;
		break;
	}
	p_flag = 0;
	outLen = 0;
	return ret;
PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//		[Location]	: HJCrypto_BlockCipher	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		fprintf(stdout, "//		[Location]	: HJCrypto_BlockCipher	//\n");
		ret = FAIL_critical;
		p_flag = 0;
		outLen = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

__declspec(dllexport) uint32_t HJCrypto_BlockCipher_init(uint32_t Enc, uint32_t mode, uint32_t type, const* masterkey, uint32_t keyLen, const uint8_t* iv) {
	uint32_t ret = success;
	uint32_t p_flag = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//	[Location]	: HJCrypto_BlockCipher_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//	[Location]	: HJCrypto_BlockCipher_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}


	//parameter Check
	if ((Enc != LEA) || ((mode != CTR) && (mode != ECB)) || ((type != ENCRYPTION) && (type != DECRYPTION))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	if ((masterkey == NULL) || ((keyLen != 16) && (keyLen != 24) && (keyLen != 32))) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	//나중에 ECB 탑재하는 경우, iv가 NULL 일 수 있음.
	if ((mode == CTR) && (iv == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	switch (mode)
	{
	case ECB:
		ret = ECB_init(&info, Enc, masterkey, keyLen, mode, type);
		if (ret != success)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_init(&info, Enc, masterkey, keyLen, mode, type, iv);
		if (ret != success)
			goto EXIT;
		break;
	default:
		goto EXIT;
		break;
	}
	return ret;
PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//	[Location]	: HJCrypto_BlockCipher_init	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		fprintf(stdout, "//	[Location]	: HJCrypto_BlockCipher_init	//\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

__declspec(dllexport) uint32_t HJCrypto_BlockCipher_Update(const uint8_t* in, uint64_t ptLen, uint8_t* out, uint64_t* outLen) {
	uint32_t ret = success;
	uint32_t p_flag = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//[Location]: HJCrypto_BlockCipher_Update	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//[Location]: HJCrypto_BlockCipher_Update	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//parameter Check
	if ((in == NULL) || (out == NULL) || (outLen == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}
	switch (info.MODE)
	{
	case ECB:
		ret = ECB_update(&info, in, ptLen, out, &outLen);
		if (ret != success)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_update(&info, in, ptLen, out, &outLen);
		if (ret != success)
			goto EXIT;
		break;
	default:
		goto EXIT;
		break;
	}
	return ret;
PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//[Location]: HJCrypto_BlockCipher_Update	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		fprintf(stdout, "//[Location]: HJCrypto_BlockCipher_Update	//\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

__declspec(dllexport) uint32_t HJCrypto_BlockCipher_final(uint8_t* out) {
	uint32_t ret = success;
	uint32_t p_flag = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//	[Location]	: HJCrypto_BlockCipher_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//	[Location]	: HJCrypto_BlockCipher_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	//parameter Check
	if ((out == NULL)) {
		p_flag = FAIL_invaild_paramter;
		goto PERR;
	}

	switch (info.MODE)
	{
	case ECB:
		ret = ECB_final(&info, out);
		if (ret != success)
			goto EXIT;
		break;
	case CTR:
		ret = CTR_final(&info, out);
		if (ret != success)
			goto EXIT;
		break;
	default:
		break;
	}
	return ret;
PERR:
	if (p_flag != success) {
		_Change_HJCrypto_state(HJ_normal_err);
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: FAIL_invaild_paramter	//\n");
		fprintf(stdout, "//	[Location]: HJCrypto_BlockCipher_final	//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Err		//\n");
		fprintf(stdout, "//		[*] state	: Change Normal Mode	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");
		_Change_HJCrypto_state(HJ_NORMAL);
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return p_flag;
	}
EXIT:
	if (ret != success) {
		ret = FAIL_critical;
		fprintf(stdout, "//	[Location]: HJCrypto_BlockCipher_final	//\n");
		p_flag = 0;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		return ret;
	}
}

__declspec(dllexport) uint32_t HJCrypto_BlockCipher_Clear(void) {
	uint32_t ret = success;
	uint32_t state = _getState();

	if ((state != HJ_NORMAL) && (state != HJ_preSELF_test)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not normal state		//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//	[Location]	: HJCrypto_BlockCipher_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	if ((state != HJ_preSELF_test) && (func_test_state.blockCipherTest != success)) {
		fprintf(stdout, "/////////////////////////////////////////////\n");
		fprintf(stdout, "//		[*] state	: Not perform KAT Test	//\n");
		fprintf(stdout, "//		[*] Reset	: HJCrypto_module		//\n");
		fprintf(stdout, "//	[Location]	: HJCrypto_BlockCipher_init	//\n");
		fprintf(stdout, "//		[*] state	: Change critical_err	//\n");
		fprintf(stdout, "/////////////////////////////////////////////\n\n");

		ret = FAIL_invaild_state;
		HJCrypto_memset(&info, 0, sizeof(blockCipher));
		_Change_HJCrypto_state(HJ_critical_err);
		HJCrypto_Finish();
		return ret;
	}

	ret = HJCrypto_memset(&info, 0, sizeof(blockCipher));
	return ret;
}