#include <assert.h>

#include <BPSecLib.h>
#include <BPSecLib_MockBPA.h>
#include "bsl_test_utils.h"

#include <policy_provider/SamplePolicyProvider.h>
#include <security_context/DefaultSecContext.h>

BSL_PolicyActionSet_t *BSLTEST_InitMallocBIBActionSet(BSL_SecRole_e role, size_t sec_param_length, BSL_SecParam_t *sec_params[sec_param_length])
{
    BSL_PolicyActionSet_t *action_set = calloc(sizeof(BSL_PolicyActionSet_t), 1);
    // Populate a PolicyActionSet with one action, of the appendix A1 BIB
    action_set->capacity = sizeof(action_set->sec_operations) / sizeof(BSL_SecOper_t);
    action_set->size = 1;
    BSL_SecOper_t *bib_oper = &action_set->sec_operations[0];
    BSL_SecOper_Init(bib_oper, 1, 1, 2, BSL_SECBLOCKTYPE_BIB, role);

    for (size_t parm_index=0; parm_index < sec_param_length; parm_index++)
    {
        BSL_SecOper_AppendParam(bib_oper, sec_params[parm_index]);
    }
    return action_set;
}

BSL_PolicyResponseSet_t *BSLTEST_MallocEmptyPolicyResponse()
{
    return calloc(sizeof(BSL_PolicyResponseSet_t), 1);
}

void BSLTEST_SetupDefaultSecurityContext(BSL_LibCtx_t *bsl_lib)
{
    assert(bsl_lib != NULL);
    
    BSL_CryptoInit();
    uint8_t rfc9171A1_key[] = { 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b,
                                0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b };
    uint8_t rfc9171A2_key[] = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                                0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70 };
    BSL_CryptoTools_AddKeyToRegistry(RFC9173_EXAMPLE_A1_KEY, rfc9171A1_key, 16);
    BSL_CryptoTools_AddKeyToRegistry(RFC9173_EXAMPLE_A2_KEY, rfc9171A2_key, 16);

    BSL_SecCtxDesc_t bib_sec_desc;
    bib_sec_desc.execute  = BSLX_ExecuteBIB;
    bib_sec_desc.validate = BSLX_ValidateBIB;
    assert(0 == BSL_LibCtx_AddSecurityContext(bsl_lib, 1, bib_sec_desc));
    
    BSL_SecCtxDesc_t bcb_sec_desc;
    bcb_sec_desc.execute  = BSLX_ExecuteBCB;
    bcb_sec_desc.validate = BSLX_ValidateBCB;
    assert(0 == BSL_LibCtx_AddSecurityContext(bsl_lib, 2, bcb_sec_desc));
}

bool BSLTEST_IsB16StrEqualTo(const char *b16_string, BSL_Data_t encoded_val)
{
    string_t in_text;
    string_init_set_str(in_text, b16_string);
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    in_data.owned = 1;
    if (base16_decode(&in_data, in_text) != 0)
    {
        BSL_Data_Deinit(&in_data);
        string_clear(in_text);
        assert(0);
        // TEST_ASSERT_MESSAGE(0, "Could not base16-decode sequence");
    }
    string_clear(in_text);

    printHex("actual str  : ", encoded_val.ptr, encoded_val.len);
    printHex("expected str: ", in_data.ptr, in_data.len);
    if (encoded_val.len != in_data.len)
    {
        BSL_LOG_ERR("Mismatch, got %lu bytes, expected %lu bytes", encoded_val.len, in_data.len);
        BSL_Data_Deinit(&in_data);
        return false;
    }

    int r = memcmp(encoded_val.ptr, in_data.ptr, in_data.len);
    BSL_Data_Deinit(&in_data);
    return r == 0 ? true : false;
}

void printHex(const char *message, uint8_t *buff, size_t bufflen)
{

    uint8_t *ascii_buf = malloc(bufflen * 2 + 10);
    memset(ascii_buf, 0, bufflen * 2 + 10);
    const char hex_digits[] = "0123456789abcdef";
    size_t     i;
    for (i = 0; i < bufflen; i++)
    {
        ascii_buf[(i * 2)]     = hex_digits[(buff[i] >> 4) & 0x0F];
        ascii_buf[(i * 2) + 1] = hex_digits[buff[i] & 0x0F];
    }
    BSL_LOG_INFO("%s :: %s", message, ascii_buf);
    free(ascii_buf);
}

int BSL_TestUtils_LoadBundleFromCBOR(BSL_TestContext_t *test_ctx, const char *cbor_seq)
{
    assert(test_ctx != NULL);
    assert(cbor_seq != NULL);

    string_t in_text;
    string_init_set_str(in_text, cbor_seq);
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    in_data.owned = 1;
    if (base16_decode(&in_data, in_text) != 0)
    {
        BSL_Data_Deinit(&in_data);
        string_clear(in_text);
        return -1;
    }
    string_clear(in_text);

    test_ctx->mock_bpa_ctr.encoded       = in_data;
    test_ctx->mock_bpa_ctr.encoded.owned = 1;

    int decode_status = mock_bpa_decode(&(test_ctx->mock_bpa_ctr), &(test_ctx->bsl));
    assert(test_ctx->mock_bpa_ctr.bundle->prim_blk.timestamp.seq_num > 0);
    assert(test_ctx->mock_bpa_ctr.bundle->prim_blk.version == 7);
    assert(test_ctx->mock_bpa_ctr.bundle->prim_blk.lifetime > 0);
    assert(test_ctx->mock_bpa_ctr.bundle->prim_blk.flags <= 64);
    assert(test_ctx->mock_bpa_ctr.bundle->prim_blk.crc_type <= 4);
    assert(BSL_BundleBlockList_size(test_ctx->mock_bpa_ctr.bundle->blks) > 0);
    return decode_status;
}

BSL_HostEIDPattern_t GetEIDPatternFromText(const char *text)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    assert(0 == BSL_HostEIDPattern_DecodeFromText(&pat, text));
    return pat;
}

RFC9173_A1_Params BSLTEST_GetRFC9173_A1Params(uint64_t key_id)
{
    RFC9173_A1_Params params = { 0 };
    BSL_SecParam_InitInt64(&params.sha_variant,
                           RFC9173_TestVectors_AppendixA1.bib_asb_sha_variant_key,
                           RFC9173_TestVectors_AppendixA1.bib_asb_sha_variant_value);
    BSL_SecParam_InitInt64(&params.scope_flags,
                           RFC9173_TestVectors_AppendixA1.bib_asb_scope_flags_key,
                           RFC9173_TestVectors_AppendixA1.bib_asb_scope_flags_value);
    BSL_SecParam_InitInt64(&params.test_key_id,
                           BSL_SECPARAM_TYPE_INT_KEY_ID,
                           key_id);
    return params;
}