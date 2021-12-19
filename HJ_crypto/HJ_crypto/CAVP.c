#define _CRT_SECURE_NO_WARNINGS
#include "HJ_crypto.h"
#include <assert.h>

extern FUNC_TEST func_test_state;

unsigned char getHex(unsigned char ch)
{
    unsigned char hex = 0;
    if (ch >= '0' && ch <= '9')
    {
        hex = ch - '0';
    }
    else if (ch >= 'a' && ch <= 'f')
    {
        hex = ch - 'a' + 10;
    }
    else if (ch >= 'A' && ch <= 'F')
    {
        hex = ch - 'A' + 10;
    }
    return hex;
}
void convertStr2Byte(unsigned char* from, int size, unsigned char* to)
{
    int cnt_i = 0;
    int cnt_j = 0;
    int ch = 0;

    for (cnt_i = 0; cnt_i < size; cnt_i += 2, cnt_j++)
    {

        ch = from[cnt_i];
        to[cnt_j] = getHex(ch);
        to[cnt_j] <<= 4;
        ch = from[cnt_i + 1];
        to[cnt_j] |= getHex(ch);
    }

}

static uint32_t CTR_ADD(uint8_t* ctr)
{
    int i = 0;
    uint8_t carry = 1;
    uint8_t temp = 0;
    for (i = 15; i >= 0; i--) {
        temp = ctr[i] + carry;
        if (temp < ctr[i])
            carry = 1;
        else
            carry = 0;
        ctr[i] = temp;
    };
}

void LEA_CTR_MCT()
{
    FILE* fp_req = NULL;
    FILE* fp_rsp = NULL;
    uint8_t buf[200] = { 0, };
    uint8_t mk[32] = { 0, };
    uint8_t IV[16] = { 0, };
    uint8_t value[16] = { 0, };
    uint8_t temp[16] = { 0, };
    uint8_t output[16] = { 0, };
    uint8_t pt[16] = { 0, };
    int count = 0;
    int i = 0;
    int j = 0;
    unsigned char* ptr = NULL;
    
    //128
    fp_req = fopen("LEA128(CTR)MCT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("LEA128(CTR)MCTrsp.txt", "w");
    assert(fp_rsp != NULL);
   
    //CounT
    fgets(buf, sizeof(buf), fp_req);

    //KEY Copy
    fgets(buf, sizeof(buf), fp_req);
    ptr = strtok(buf, " =");// 공백과 띄어쓰기 무시
    ptr = strtok(NULL, " =");
    convertStr2Byte(ptr, 32, mk);
    //IV Copy
    fgets(buf, sizeof(buf), fp_req);
    ptr = strtok(buf, " =");// 공백과 띄어쓰기 무시
    ptr = strtok(NULL, " =");
    convertStr2Byte(ptr, 32, IV);

    //PT copy
    fgets(buf, sizeof(buf), fp_req);
    ptr = strtok(buf, " =");// 공백과 띄어쓰기 무시
    ptr = strtok(NULL, " =");
    convertStr2Byte(ptr, 32, pt);

    for (count = 0; count < 100; count++)
    {
        fprintf(fp_rsp, "COUNT = %d\n", count);

        //key
        fprintf(fp_rsp, "KEY = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", mk[j]);
        fprintf(fp_rsp, "\n");

        ///IV
        fprintf(fp_rsp, "CTR = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", IV[j]);
        fprintf(fp_rsp, "\n");

        //PT
        fprintf(fp_rsp, "PT = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", pt[j]);
        fprintf(fp_rsp, "\n");

        for (i = 0; i < 1000; i++) {
            HJCrypto_BlockCipher(LEA, CTR, ENCRYPTION, mk, 16, pt, 16, IV, output);
            CTR_ADD(IV);
            for (int c = 0; c < 16; c++) {
                pt[c] = output[c];
            }
        }
        //key
        for (int c = 0; c < 16; c++)
            mk[c] ^= output[c];

        fprintf(fp_rsp, "CT = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", output[j]);
        fprintf(fp_rsp, "\n\n");
    }
    fclose(fp_req);
    fclose(fp_rsp);
    HJCrypto_memset(buf, 0, sizeof(buf));
    HJCrypto_memset(mk, 0, sizeof(mk));
    HJCrypto_memset(IV, 0, sizeof(IV));
    HJCrypto_memset(value, 0, sizeof(value));
    HJCrypto_memset(temp, 0, sizeof(temp));
    HJCrypto_memset(pt, 0, sizeof(pt));
    //192
    fp_req = fopen("LEA192(CTR)MCT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("LEA192(CTR)MCTrsp.txt", "w");
    assert(fp_rsp != NULL);

    //CounT
    fgets(buf, sizeof(buf), fp_req);

    //KEY Copy
    fgets(buf, sizeof(buf), fp_req);
    ptr = strtok(buf, " =");// 공백과 띄어쓰기 무시
    ptr = strtok(NULL, " =");
    convertStr2Byte(ptr, 48, mk);
    //IV Copy
    fgets(buf, sizeof(buf), fp_req);
    ptr = strtok(buf, " =");// 공백과 띄어쓰기 무시
    ptr = strtok(NULL, " =");
    convertStr2Byte(ptr, 32, IV);

    //PT copy
    fgets(buf, sizeof(buf), fp_req);
    ptr = strtok(buf, " =");// 공백과 띄어쓰기 무시
    ptr = strtok(NULL, " =");
    convertStr2Byte(ptr, 32, pt);

    for (count = 0; count < 100; count++)
    {
        fprintf(fp_rsp, "COUNT = %d\n", count);

        //key
        fprintf(fp_rsp, "KEY = ");
        for (j = 0; j < 24; j++)
            fprintf(fp_rsp, "%02X", mk[j]);
        fprintf(fp_rsp, "\n");

        ///IV
        fprintf(fp_rsp, "CTR = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", IV[j]);
        fprintf(fp_rsp, "\n");

        //PT
        fprintf(fp_rsp, "PT = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", pt[j]);
        fprintf(fp_rsp, "\n");

        for (i = 0; i < 1000; i++) {
            HJCrypto_BlockCipher(LEA, CTR, ENCRYPTION, mk, 24, pt, 16, IV, output);
            CTR_ADD(IV);
            for (int c = 0; c < 16; c++) {
                pt[c] = output[c];
            }
            if (i == 998)
                memcpy(temp, output, 16);
        }
        //key
        for (int c = 0; c < 8; c++)
            mk[c] ^= temp[c + 8];
        for (int c = 8; c < 24; c++)
            mk[c] ^= output[c - 8];

        fprintf(fp_rsp, "CT = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", output[j]);
        fprintf(fp_rsp, "\n\n");
    }
    fclose(fp_req);
    fclose(fp_rsp);

    HJCrypto_memset(buf, 0, sizeof(buf));
    HJCrypto_memset(mk, 0, sizeof(mk));
    HJCrypto_memset(IV, 0, sizeof(IV));
    HJCrypto_memset(value, 0, sizeof(value));
    HJCrypto_memset(temp, 0, sizeof(temp));
    HJCrypto_memset(pt, 0, sizeof(pt));
    //256
    fp_req = fopen("LEA256(CTR)MCT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("LEA256(CTR)MCT_rsp.txt", "w");
    assert(fp_rsp != NULL);

    //CounT
    fgets(buf, sizeof(buf), fp_req);

    //KEY Copy
    fgets(buf, sizeof(buf), fp_req);
    ptr = strtok(buf, " =");// 공백과 띄어쓰기 무시
    ptr = strtok(NULL, " =");
    convertStr2Byte(ptr, 64, mk);
    //IV Copy
    fgets(buf, sizeof(buf), fp_req);
    ptr = strtok(buf, " =");// 공백과 띄어쓰기 무시
    ptr = strtok(NULL, " =");
    convertStr2Byte(ptr, 32, IV);

    //PT copy
    fgets(buf, sizeof(buf), fp_req);
    ptr = strtok(buf, " =");// 공백과 띄어쓰기 무시
    ptr = strtok(NULL, " =");
    convertStr2Byte(ptr, 32, pt);

    for (count = 0; count < 100; count++)
    {
        fprintf(fp_rsp, "COUNT = %d\n", count);

        //key
        fprintf(fp_rsp, "KEY = ");
        for (j = 0; j < 32; j++)
            fprintf(fp_rsp, "%02X", mk[j]);
        fprintf(fp_rsp, "\n");

        ///IV
        fprintf(fp_rsp, "CTR = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", IV[j]);
        fprintf(fp_rsp, "\n");

        //PT
        fprintf(fp_rsp, "PT = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", pt[j]);
        fprintf(fp_rsp, "\n");

        for (i = 0; i < 1000; i++) {
            HJCrypto_BlockCipher(LEA, CTR, ENCRYPTION, mk, 32, pt, 16, IV, output);
            CTR_ADD(IV);
            for (int c = 0; c < 16; c++) {
                pt[c] = output[c];
            }
            if (i == 998)
                memcpy(temp, output, 16);
        }
        //key
        for (int c = 0; c < 16; c++)
            mk[c] ^= temp[c];
        for (int c = 16; c < 32; c++)
            mk[c] ^= output[c - 16];

        fprintf(fp_rsp, "CT = ");
        for (j = 0; j < 16; j++)
            fprintf(fp_rsp, "%02X", output[j]);
        fprintf(fp_rsp, "\n\n");
    }
    fclose(fp_req);
    fclose(fp_rsp);
    ptr = NULL;
    HJCrypto_memset(buf, 0, sizeof(buf));
    HJCrypto_memset(mk, 0, sizeof(mk));
    HJCrypto_memset(IV, 0, sizeof(IV));
    HJCrypto_memset(value, 0, sizeof(value));
    HJCrypto_memset(temp, 0, sizeof(temp));
    HJCrypto_memset(pt, 0, sizeof(pt));
}

void LEA_CTR_KAT() {
    FILE* fp_req = NULL;
    FILE* fp_rsp = NULL;
    unsigned char* pont = NULL;
    fp_req = fopen("LEA128(CTR)KAT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("LEA128(CTR)KATrsp.txt", "w");
    assert(fp_rsp != NULL);

    uint8_t PT[16] = { 0, };
    uint8_t KEY[32] = { 0, };
    uint8_t CT[16] = { 0, };
    uint8_t iv[16] = { 0, };
    uint8_t buf[2000] = { 0, };

    int i = 0;

    while (!feof(fp_req)) {
        if (feof(fp_req))
            break;

        fgets((char*)buf, sizeof(buf), fp_req);

        if (strnlen(buf, sizeof(buf)) > 5) {

            fprintf(fp_rsp, "%s", buf);
            pont = strtok((char*)buf, " =");
            pont = strtok(NULL, " =");
            convertStr2Byte(pont, 32, KEY);

            fgets((char*)buf, sizeof(buf), fp_req);
            fprintf(fp_rsp, "%s", buf);
            pont = strtok((char*)buf, " =");
            pont = strtok(NULL, " =");
            convertStr2Byte(pont, 32, iv);

            fgets((char*)buf, sizeof(buf), fp_req);
            fprintf(fp_rsp, "%s", buf);
            pont = strtok((char*)buf, " =");
            pont = strtok(NULL, " =");
            convertStr2Byte(pont, 32, PT);
            _Change_HJCrypto_state(HJ_NORMAL);
            HJCrypto_BlockCipher(LEA, CTR, ENCRYPTION, KEY, 16, PT, 16, iv, CT);
            fprintf(fp_rsp, "CT = ");
            for (i = 0; i < 16; i++) {
                fprintf(fp_rsp, "%02X", CT[i]);
            }
            fprintf(fp_rsp, "\n\n");
            fgets((char*)buf, sizeof(buf), fp_req);
        }
    }
    fclose(fp_req);
    fclose(fp_rsp);

    fp_req = fopen("LEA192(CTR)KAT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("LEA192(CTR)KATrsp.txt", "w");
    assert(fp_rsp != NULL);
    while (!feof(fp_req)) {
        if (feof(fp_req))
            break;

        fgets((char*)buf, sizeof(buf), fp_req);
        if (strnlen(buf, sizeof(buf)) > 5) {

            fprintf(fp_rsp, "%s", buf);
            pont = strtok((char*)buf, " =");
            pont = strtok(NULL, " =");
            convertStr2Byte(pont, 48, KEY);

            fgets((char*)buf, sizeof(buf), fp_req);
            fprintf(fp_rsp, "%s", buf);
            pont = strtok((char*)buf, " =");
            pont = strtok(NULL, " =");
            convertStr2Byte(pont, 32, iv);

            fgets((char*)buf, sizeof(buf), fp_req);
            fprintf(fp_rsp, "%s", buf);
            pont = strtok((char*)buf, " =");
            pont = strtok(NULL, " =");
            convertStr2Byte(pont, 32, PT);
            _Change_HJCrypto_state(HJ_NORMAL);
            HJCrypto_BlockCipher(LEA, CTR, ENCRYPTION, KEY, 24, PT, 16, iv, CT);
            fprintf(fp_rsp, "CT = ");
            for (i = 0; i < 16; i++) {
                fprintf(fp_rsp, "%02X", CT[i]);
            }
            fprintf(fp_rsp, "\n\n");
            fgets((char*)buf, sizeof(buf), fp_req);
        }
    }
    fclose(fp_req);
    fclose(fp_rsp);

    fp_req = fopen("LEA256(CTR)KAT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("LEA256(CTR)KATrsp.txt", "w");
    assert(fp_rsp != NULL);
    while (!feof(fp_req)) {
        if (feof(fp_req))
            break;

        fgets((char*)buf, sizeof(buf), fp_req);
        if (strnlen(buf, sizeof(buf)) > 5) {

            fprintf(fp_rsp, "%s", buf);
            pont = strtok((char*)buf, " =");
            pont = strtok(NULL, " =");
            convertStr2Byte(pont, 64, KEY);

            fgets((char*)buf, sizeof(buf), fp_req);
            fprintf(fp_rsp, "%s", buf);
            pont = strtok((char*)buf, " =");
            pont = strtok(NULL, " =");
            convertStr2Byte(pont, 32, iv);

            fgets((char*)buf, sizeof(buf), fp_req);
            fprintf(fp_rsp, "%s", buf);
            pont = strtok((char*)buf, " =");
            pont = strtok(NULL, " =");
            convertStr2Byte(pont, 32, PT);
            _Change_HJCrypto_state(HJ_NORMAL);
            HJCrypto_BlockCipher(LEA, CTR, ENCRYPTION, KEY, 32, PT, 16, iv, CT);
            fprintf(fp_rsp, "CT = ");
            for (i = 0; i < 16; i++) {
                fprintf(fp_rsp, "%02X", CT[i]);
            }
            fprintf(fp_rsp, "\n\n");
            fgets((char*)buf, sizeof(buf), fp_req);
        }
    }
    fclose(fp_req);
    fclose(fp_rsp);

    HJCrypto_memset(PT, 0, 16);
    HJCrypto_memset(CT, 0, 16);
    HJCrypto_memset(iv, 0, 16);
    HJCrypto_memset(KEY, 0, 32);
    HJCrypto_memset(buf, 0, 2000);
}

void LEA_CTR_MMT()
{
    int cnt_i = 0, cnt_j = 0, cnt_k = 0, num_count = 0;
    FILE* fp_req = NULL;
    FILE* fp_rsp = NULL;
    uint8_t buffer[3096];
    uint8_t* ptr = NULL;
    uint8_t mk[32];
    uint8_t iv[16];
    uint8_t pt[3096];
    uint8_t ct[3096];
    uint32_t index = 32;
    uint32_t i = 0;
    fp_req = fopen("LEA128(CTR)MMT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("LEA128(CTR)MMTrsp.txt", "w");
    assert(fp_rsp != NULL);

    while (!feof(fp_req)) {
        if (feof(fp_req))
            break;

        fgets((char*)buffer, sizeof(buffer), fp_req);
        if (strnlen(buffer, sizeof(buffer)) > 5) {

            //key
            fprintf(fp_rsp, "%s", buffer);
            ptr = strtok((char*)buffer, " =");
            ptr = strtok(NULL, " =");
            convertStr2Byte(ptr, 32, mk);

            //iv
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            ptr = strtok((char*)buffer, " =");
            ptr = strtok(NULL, " =");
            convertStr2Byte(ptr, 32, iv);

            //PT
            fgets((char*)buffer, sizeof(buffer), fp_req);
            index = strlen(buffer) - 6;
            fprintf(fp_rsp, "%s", buffer);
            ptr = strtok((char*)buffer, " =");
            ptr = strtok(NULL, " =");
            convertStr2Byte(ptr, index, pt);
            

            _Change_HJCrypto_state(HJ_NORMAL);
            func_test_state.blockCipherTest = success;
            HJCrypto_BlockCipher(LEA, CTR, ENCRYPTION, mk, 16, pt, index/2, iv, ct);
            fprintf(fp_rsp, "CT = ");
            for (int i = 0; i < index/2; i++) {
                fprintf(fp_rsp, "%02X", ct[i]);
            }
            fprintf(fp_rsp, "\n\n");
            fgets((char*)buffer, sizeof(buffer), fp_req);
        }
    }
    fclose(fp_req);
    fclose(fp_rsp);
    fp_req = fopen("LEA192(CTR)MMT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("LEA192(CTR)MMTrsp.txt", "w");
    assert(fp_rsp != NULL);

    while (!feof(fp_req)) {
        if (feof(fp_req))
            break;

        fgets((char*)buffer, sizeof(buffer), fp_req);
        if (strnlen(buffer, sizeof(buffer)) > 5) {

            //key
            fprintf(fp_rsp, "%s", buffer);
            ptr = strtok((char*)buffer, " =");
            ptr = strtok(NULL, " =");
            convertStr2Byte(ptr, 48, mk);

            //iv
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            ptr = strtok((char*)buffer, " =");
            ptr = strtok(NULL, " =");
            convertStr2Byte(ptr, 32, iv);

            //PT
            fgets((char*)buffer, sizeof(buffer), fp_req);
            index = strlen(buffer) - 6;
            fprintf(fp_rsp, "%s", buffer);
            ptr = strtok((char*)buffer, " =");
            ptr = strtok(NULL, " =");
            convertStr2Byte(ptr, index, pt);


            _Change_HJCrypto_state(HJ_NORMAL);
            func_test_state.blockCipherTest = success;
            HJCrypto_BlockCipher(LEA, CTR, ENCRYPTION, mk, 24, pt, index / 2, iv, ct);
            fprintf(fp_rsp, "CT = ");
            for (int i = 0; i < index / 2; i++) {
                fprintf(fp_rsp, "%02X", ct[i]);
            }
            fprintf(fp_rsp, "\n\n");
            fgets((char*)buffer, sizeof(buffer), fp_req);
        }
    }
    fclose(fp_req);
    fclose(fp_rsp);
    fp_req = fopen("LEA256(CTR)MMT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("LEA256(CTR)MMTrsp.txt", "w");
    assert(fp_rsp != NULL);

    while (!feof(fp_req)) {
        if (feof(fp_req))
            break;

        fgets((char*)buffer, sizeof(buffer), fp_req);
        if (strnlen(buffer, sizeof(buffer)) > 5) {

            //key
            fprintf(fp_rsp, "%s", buffer);
            ptr = strtok((char*)buffer, " =");
            ptr = strtok(NULL, " =");
            convertStr2Byte(ptr, 64, mk);

            //iv
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            ptr = strtok((char*)buffer, " =");
            ptr = strtok(NULL, " =");
            convertStr2Byte(ptr, 32, iv);

            //PT
            fgets((char*)buffer, sizeof(buffer), fp_req);
            index = strlen(buffer) - 6;
            fprintf(fp_rsp, "%s", buffer);
            ptr = strtok((char*)buffer, " =");
            ptr = strtok(NULL, " =");
            convertStr2Byte(ptr, index, pt);


            _Change_HJCrypto_state(HJ_NORMAL);
            func_test_state.blockCipherTest = success;
            HJCrypto_BlockCipher(LEA, CTR, ENCRYPTION, mk, 32, pt, index / 2, iv, ct);
            fprintf(fp_rsp, "CT = ");
            for (int i = 0; i < index / 2; i++) {
                fprintf(fp_rsp, "%02X", ct[i]);
            }
            fprintf(fp_rsp, "\n\n");
            fgets((char*)buffer, sizeof(buffer), fp_req);
        }
    }
    fclose(fp_req);
    fclose(fp_rsp);
    HJCrypto_memset(buffer, 0, 3096);
    HJCrypto_memset(mk, 0, 32);
    HJCrypto_memset(iv, 0, 16);
    HJCrypto_memset(pt, 0, 3096);
    HJCrypto_memset(ct, 0, 3096);
}


static uint32_t str2hex(uint8_t* out, char* in) {
    uint32_t ret = 0;
    while (in[ret] != '\0') {
        out[ret] = in[ret];
        ret++;
    }
    return ret;
}

static uint32_t asci2hex(uint8_t* out, uint8_t* in) {
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t ch = 0;
    while (in[i] != 0x00) {
        ch = in[i];
        out[j] = getHex(ch);
        out[j] <<= 4;
        ch = in[i + 1];
        out[j] |= getHex(ch);
        i = i + 2;
        j = j + 1;
    }
    return j;
}

static uint32_t asci2hex_2(uint8_t* out, uint8_t* in, uint32_t size) {
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t ch = 0;
    for (i = 0; i < size; i+=2){
        ch = in[i];
        out[j] = getHex(ch);
        out[j] <<= 4;
        ch = in[i + 1];
        out[j] |= getHex(ch);
        j = j + 1;
    }
    return j;
}

void HMAC_DBBG_CAVP()
{
    char* ptr = NULL;
    uint8_t buffer[2048];
    FILE* fp_req = NULL;
    FILE* fp_rsp = NULL;
    uint32_t PR_FLAG;

    uint8_t Entropy[512];
    uint8_t Nonce[512];
    uint8_t per[512];
    uint8_t EntropyPR1[512];
    uint8_t EntropyPR2[512];
    uint8_t Add1[512];
    uint8_t Add2[512];
    uint8_t tv_result[512];
    uint8_t HJ_result[512];
    uint32_t EntropyLen = 0;
    uint32_t EntropyPR1_Len = 0;
    uint32_t EntropyPR2_Len = 0;
    uint32_t NonceLen = 0;
    uint32_t perLen = 0;
    uint32_t Add1Len = 0;
    uint32_t Add2Len = 0;
    uint32_t resultLen = 128;
    uint32_t i = 0;

    fp_req = fopen("HMAC_DRBG(SHA256(use PR))_KAT.txt", "r");
    assert(fp_req != NULL);
    fp_rsp = fopen("HMAC_DRBG(SHA256(use PR))_KAT_rsp.txt", "w");
    assert(fp_rsp != NULL);
    uint32_t count = 0;
    //SHA256 날리기
    fgets((char*)buffer, sizeof(buffer), fp_req);

    //pre
    fgets((char*)buffer, sizeof(buffer), fp_req);
    ptr = strtok((char*)buffer, " =");
    ptr = strtok(NULL, " =");
    PR_FLAG = USE_PR;
    fseek(fp_req, 0, SEEK_SET);

    //ENLEN
    fgets((char*)buffer, sizeof(buffer), fp_req);
    fprintf(fp_rsp, "%s", buffer);
    fgets((char*)buffer, sizeof(buffer), fp_req);
    fprintf(fp_rsp, "%s", buffer);
    fgets((char*)buffer, sizeof(buffer), fp_req);
    fprintf(fp_rsp, "%s", buffer);
    fgets((char*)buffer, sizeof(buffer), fp_req);
    fprintf(fp_rsp, "%s", buffer);
    fgets((char*)buffer, sizeof(buffer), fp_req);
    fprintf(fp_rsp, "%s", buffer);
    fgets((char*)buffer, sizeof(buffer), fp_req);
    fprintf(fp_rsp, "%s", buffer);
    fgets((char*)buffer, sizeof(buffer), fp_req);
    fprintf(fp_rsp, "%s", buffer);
    fgets((char*)buffer, sizeof(buffer), fp_req);
    fprintf(fp_rsp, "%s", buffer);

  

            for (int x = 0; x < 15; x++) {

                //COUNTER
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);

                //ENTROPY
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyLen = asci2hex_2(Entropy, ptr, count);
                EntropyLen = count / 2;

                //Nonce
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                NonceLen = asci2hex_2(Nonce, ptr, count);
                NonceLen = count / 2;

                //PersonalizationString 
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                perLen = asci2hex_2(per, ptr, count);
                perLen = count / 2;

                //EntropyInputPR  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyPR1_Len = asci2hex_2(EntropyPR1, ptr, count);
                EntropyPR1_Len = count / 2;

                //AdditionalInput 1  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                Add1Len = asci2hex_2(Add1, ptr, count);
                Add1Len = count / 2;

                //EntropyInputPR2  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyPR2_Len = asci2hex_2(EntropyPR2, ptr, count);
                EntropyPR2_Len = count / 2;

                //AdditionalInput 2  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                Add2Len = asci2hex_2(Add2, ptr, count);
                Add2Len = count / 2;

                _Change_HJCrypto_state(HJ_NORMAL);
                func_test_state.DRBGTest = success;
                HJCrypto_HMAC_DRBG_Instantiate(HMAC_SHA256, Entropy, EntropyLen, Nonce, NonceLen, per, perLen, PR_FLAG);
                HJCrypto_HMAC_DRBG_Generate(HJ_result, resultLen, EntropyPR1, EntropyPR1_Len, Add1, Add1Len, PR_FLAG);
                HJCrypto_HMAC_DRBG_Generate(HJ_result, resultLen, EntropyPR2, EntropyPR2_Len, Add2, Add2Len, PR_FLAG);

                fprintf(fp_rsp, "ReturnedBits   = ");
                for (int i = 0; i < resultLen; i++) {
                    fprintf(fp_rsp, "%02X", HJ_result[i]);
                }
                fprintf(fp_rsp, "\n\n");
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fgets((char*)buffer, sizeof(buffer), fp_req);
            }

            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);



            for (int x = 0; x < 15; x++) {

                //COUNTER
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);

                //ENTROPY
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyLen = asci2hex_2(Entropy, ptr, count);
                EntropyLen = count / 2;

                //Nonce
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                NonceLen = asci2hex_2(Nonce, ptr, count);
                NonceLen = count / 2;

                //PersonalizationString 
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                perLen = asci2hex_2(per, ptr, count);
                perLen = count / 2;

                //EntropyInputPR  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyPR1_Len = asci2hex_2(EntropyPR1, ptr, count);
                EntropyPR1_Len = count / 2;

                //AdditionalInput 1  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                Add1Len = asci2hex_2(Add1, ptr, count);
                Add1Len = count / 2;

                //EntropyInputPR2  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyPR2_Len = asci2hex_2(EntropyPR2, ptr, count);
                EntropyPR2_Len = count / 2;

                //AdditionalInput 2  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                Add2Len = asci2hex_2(Add2, ptr, count);
                Add2Len = count / 2;

                _Change_HJCrypto_state(HJ_NORMAL);
                func_test_state.DRBGTest = success;
                HJCrypto_HMAC_DRBG_Instantiate(HMAC_SHA256, Entropy, EntropyLen, Nonce, NonceLen, per, perLen, PR_FLAG);
                HJCrypto_HMAC_DRBG_Generate(HJ_result, resultLen, EntropyPR1, EntropyPR1_Len, Add1, Add1Len, PR_FLAG);
                HJCrypto_HMAC_DRBG_Generate(HJ_result, resultLen, EntropyPR2, EntropyPR2_Len, Add2, Add2Len, PR_FLAG);

                fprintf(fp_rsp, "ReturnedBits   = ");
                for (int i = 0; i < resultLen; i++) {
                    fprintf(fp_rsp, "%02X", HJ_result[i]);
                }
                fprintf(fp_rsp, "\n\n");
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fgets((char*)buffer, sizeof(buffer), fp_req);
            }
        
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);



            for (int x = 0; x < 15; x++) {

                //COUNTER
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);

                //ENTROPY
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyLen = asci2hex_2(Entropy, ptr, count);
                EntropyLen = count / 2;

                //Nonce
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                NonceLen = asci2hex_2(Nonce, ptr, count);
                NonceLen = count / 2;

                //PersonalizationString 
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                perLen = asci2hex_2(per, ptr, count);
                perLen = count / 2;

                //EntropyInputPR  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyPR1_Len = asci2hex_2(EntropyPR1, ptr, count);
                EntropyPR1_Len = count / 2;

                //AdditionalInput 1  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                Add1Len = asci2hex_2(Add1, ptr, count);
                Add1Len = count / 2;

                //EntropyInputPR2  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyPR2_Len = asci2hex_2(EntropyPR2, ptr, count);
                EntropyPR2_Len = count / 2;

                //AdditionalInput 2  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                Add2Len = asci2hex_2(Add2, ptr, count);
                Add2Len = count / 2;

                _Change_HJCrypto_state(HJ_NORMAL);
                func_test_state.DRBGTest = success;
                HJCrypto_HMAC_DRBG_Instantiate(HMAC_SHA256, Entropy, EntropyLen, Nonce, NonceLen, per, perLen, PR_FLAG);
                HJCrypto_HMAC_DRBG_Generate(HJ_result, resultLen, EntropyPR1, EntropyPR1_Len, Add1, Add1Len, PR_FLAG);
                HJCrypto_HMAC_DRBG_Generate(HJ_result, resultLen, EntropyPR2, EntropyPR2_Len, Add2, Add2Len, PR_FLAG);

                fprintf(fp_rsp, "ReturnedBits   = ");
                for (int i = 0; i < resultLen; i++) {
                    fprintf(fp_rsp, "%02X", HJ_result[i]);
                }
                fprintf(fp_rsp, "\n\n");
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fgets((char*)buffer, sizeof(buffer), fp_req);
            }

            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);
            fgets((char*)buffer, sizeof(buffer), fp_req);
            fprintf(fp_rsp, "%s", buffer);



            for (int x = 0; x < 15; x++) {

                //COUNTER
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);

                //ENTROPY
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyLen = asci2hex_2(Entropy, ptr, count);
                EntropyLen = count / 2;

                //Nonce
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                NonceLen = asci2hex_2(Nonce, ptr, count);
                NonceLen = count / 2;

                //PersonalizationString 
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                perLen = asci2hex_2(per, ptr, count);
                perLen = count / 2;

                //EntropyInputPR  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyPR1_Len = asci2hex_2(EntropyPR1, ptr, count);
                EntropyPR1_Len = count / 2;

                //AdditionalInput 1  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                Add1Len = asci2hex_2(Add1, ptr, count);
                Add1Len = count / 2;

                //EntropyInputPR2  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                EntropyPR2_Len = asci2hex_2(EntropyPR2, ptr, count);
                EntropyPR2_Len = count / 2;

                //AdditionalInput 2  
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fprintf(fp_rsp, "%s", buffer);
                ptr = strtok((char*)buffer, " =");
                ptr = strtok(NULL, " =");
                count = strlen(ptr);
                count = count - 1;

                Add2Len = asci2hex_2(Add2, ptr, count);
                Add2Len = count / 2;

                _Change_HJCrypto_state(HJ_NORMAL);
                func_test_state.DRBGTest = success;
                HJCrypto_HMAC_DRBG_Instantiate(HMAC_SHA256, Entropy, EntropyLen, Nonce, NonceLen, per, perLen, PR_FLAG);
                HJCrypto_HMAC_DRBG_Generate(HJ_result, resultLen, EntropyPR1, EntropyPR1_Len, Add1, Add1Len, PR_FLAG);
                HJCrypto_HMAC_DRBG_Generate(HJ_result, resultLen, EntropyPR2, EntropyPR2_Len, Add2, Add2Len, PR_FLAG);

                fprintf(fp_rsp, "ReturnedBits   = ");
                for (int i = 0; i < resultLen; i++) {
                    fprintf(fp_rsp, "%02X", HJ_result[i]);
                }
                fprintf(fp_rsp, "\n\n");
                fgets((char*)buffer, sizeof(buffer), fp_req);
                fgets((char*)buffer, sizeof(buffer), fp_req);
            }
            HJCrypto_memset(Entropy, 0, sizeof(Entropy));
            HJCrypto_memset(Nonce, 0, sizeof(Nonce));
            HJCrypto_memset(EntropyPR1, 0, sizeof(EntropyPR1));
            HJCrypto_memset(EntropyPR2, 0, sizeof(EntropyPR2));
            HJCrypto_memset(Add1, 0, sizeof(Add1));
            HJCrypto_memset(Add2, 0, sizeof(Add2));
            HJCrypto_memset(tv_result, 0, sizeof(tv_result));
            HJCrypto_memset(HJ_result, 0, sizeof(HJ_result));
            HJCrypto_memset(per, 0, sizeof(per));
}