#ifndef _BSL_TEST_UTILS_H_
#define _BSL_TEST_UTILS_H_

#include <backend/DynBundleContext.h>
#include <backend/DeprecatedLibContext.h>
#include <mock_bpa/mock_bpa_ctr.h>

/// @brief Key ID for the Appendix A1 key in OpenSSL
#define RFC9173_EXAMPLE_A1_KEY (9100)

/// @brief Key ID for the Appendix A2 key in OpenSSL
#define RFC9173_EXAMPLE_A2_KEY (9101)

/// @brief Hardcoded single struct with fields populated from test vector in Appendix A1 for BIB.
static const struct RFC9173_TestVectors_AppendixA1 {
    uint64_t prim_bp_version;
    uint64_t prim_flags;
    uint64_t prim_crc_type;
    uint64_t prim_seq_number;
    uint64_t prim_lifetime;
    uint64_t payload_type_code;
    uint64_t payload_block_num;
    uint64_t payload_flags;
    uint16_t payload_crc_type;

    uint64_t bib_asb_sec_target;
    uint64_t bib_asb_context_id;
    uint64_t bib_asb_blk_num;
    uint64_t bib_asb_context_flags;
    uint64_t bib_asb_sha_variant_key;
    uint64_t bib_asb_sha_variant_value;
    uint64_t bib_asb_scope_flags_key;
    uint64_t bib_asb_scope_flags_value;

    const char *cbor_bundle_original;
    const char *cbor_bundle_bib;
    const char *cbor_payload_block;
    const char *cbor_primary_block;
    const char *cbor_bib_block;
    const char *cbor_bib_abs_sec_block;
    const char *cbor_hmac;
} RFC9173_TestVectors_AppendixA1 = {
    // Bundle primary and payload block fields.
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.1
    7,       // prim_bp_version
    0,       // prim_flags
    0,       // prim_crc_type
    40,      // prim_seq_num
    1000000, // prim_lifetime
    1,       // payload_type_code
    1,       // payload_block_num
    0,       // payload_flags
    0,       // payload_crc_type
    
    // BIB Abstract Security block fields
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.3.2
    1,       // bib_asb_sec_target
    1,       // bib_asb_context_id
    2,       // bib_asb_blk_num
    1,       // bib_asb_context_flags
    1,       // bib_asb_sha_variant_key
    7,       // bib_asb_sha_variant_value (HMAC 512/512)
    3,       // bib_asb_scope_flags_key
    0,       // bib_asb_scope_flags_value (No additional scope)

    // TODO(bvb) - Encodings of endpoints.

    // bundle_original: The full bundle without any security
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3
    ("9f88070000820282010282028202018202820201820018281a000f424085010100"
     "005823526561647920746f2067656e657261746520612033322d6279746520706179"
     "6c6f6164ff"),

    // bundle_bib: The full bundle encoding with BIB block
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.4
    ("9f88070000820282010282028202018202820201820018281a000f4240850b0200"
     "005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a"
     "8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2"
     "f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920"
     "746f2067656e657261746520612033322d62797465207061796c6f6164ff"),

    // payload_block: The CBOR of just the payload block
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.2
    ("85010100005823526561647920746f2067656e657261746520612033322d627974"
     "65207061796c6f6164"),

    // primary_block: CBOR of just the primary block
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.1
    ("88070000820282010282028202018202820201820018281a000f4240"),

    // bib_block: CBOR encoding of the BIB block (headers and all)
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.3.3
    ("850b0200005856810101018202820201828201078203008181820158403bdc69b3"
     "a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1c"
     "c636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1"),

    // bib_abs_sec_block: Encoding of the BIB Block-Type-Specific Data (Abstract Security Block)
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.3.2
    ("810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554"
     "368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a7"
     "3e303dcd4b6ccece003e95e8164dcc89a156e1"),

    // hmac: The actual HMAC digest (not including result type)
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.3.2
    ("3bdc69b3a34a2b5d3a8554368bd1e808"
     "f606219d2a10a846eae3886ae4ecc83c"
     "4ee550fdfb1cc636b904e2f1a73e303d"
     "cd4b6ccece003e95e8164dcc89a156e1")

};

static const struct RFC9173_TestVectors_AppendixA2 {
    const char *cbor_bundle_original;
    const char *cbor_authtag;
    const char *cbor_payload_ciphertext;
    const char *cbor_payload_plaintext;
    const char *cbor_bundle_final;
    const char *cbor_bundle_final_err_bytes;
} RFC9173_TestVectors_AppendixA2 = {
    ("9f88070000820282010282028202018202820201820018281a000f424085010100"
    "005823526561647920746f2067656e657261746520612033322d6279746520706179"
    "6c6f6164ff"),
    "efa4b5ac0108e3816c5606479801bc04",
    "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a",
    "526561647920746f2067656e657261746520612033322d62797465207061796c6f6164",
    ("9f88070000820282010282028202018202820201820018281a000f4240850c0201"
    "0058508101020182028202018482014c5477656c7665313231323132820201820358"
    "1869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150ef"
    "a4b5ac0108e3816c5606479801bc04850101000058233a09c1e63fe23a7f66a59c73"
    "03837241e070b02619fc59c5214a22f08cd70795e73e9aff"),
     ("9f88070000820282010282028202018202820201820018281a000f4240850c0201"
    "0058508101020182028202018482014c5477656c7665313231323132820201820358"
    "1869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150ef"
    "a4b5ac0108e3816c5606479801bc0485010100005823ffffc1e63fe23a7f66a59c73"
    "03837241e070b02619fc59c5214a22f08cd70795e73e9aff")
};

typedef struct {
    BSL_SecParam_t sha_variant;
    BSL_SecParam_t scope_flags;
    BSL_SecParam_t test_key_id;
} RFC9173_A1_Params;

RFC9173_A1_Params BSLTEST_GetRFC9173_A1Params(uint64_t key_id);

typedef struct BSL_TestContext_s 
{
    BSL_LibCtx_t   bsl;
    mock_bpa_ctr_t mock_bpa_ctr;
    // BSL_BundleCtx_t    *bundle;
    uint64_t key_id;
} BSL_TestContext_t;

BSL_PolicyActionSet_t *BSLTEST_InitMallocBIBActionSet(BSL_SecRole_e role, size_t sec_param_length, BSL_SecParam_t *sec_params[sec_param_length]);
BSL_PolicyResponseSet_t *BSLTEST_MallocEmptyPolicyResponse();

void BSLTEST_SetupDefaultSecurityContext(BSL_LibCtx_t *bsl_lib);

int BSL_TestUtils_LoadBundleFromCBOR(BSL_TestContext_t *test_ctx, const char *cbor_seq);
BSL_HostEIDPattern_t GetEIDPatternFromText(const char *text);

void printHex(const char *message, uint8_t *buff, size_t bufflen);
bool BSLTEST_IsB16StrEqualTo(const char *b16_string, BSL_Data_t encoded_val);


#endif
