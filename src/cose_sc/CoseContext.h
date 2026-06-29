/*
 * Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
 * Laboratory LLC.
 *
 * This file is part of the Bundle Protocol Security Library (BSL).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This work was performed for the Jet Propulsion Laboratory, California
 * Institute of Technology, sponsored by the United States Government under
 * the prime contract 80NM0018D0004 between the Caltech and NASA under
 * subcontract 1700763.
 */

/** @file
 * @ingroup cose_sc
 * Header for the implementation of the COSE context @cite draft-ietf-dtn-bpsec-cose.
 */

#ifndef BSLX_COSECONTEXT_H_
#define BSLX_COSECONTEXT_H_

#include <BPSecLib_Private.h>
#include <BPSecLib_Public.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Registered BPSec context ID
#define BSLX_COSESC_CTX_ID 3

/// Internal option enumerations
enum BSLX_CoseSC_Option_e
{
    /** Key ID as a byte string.
     * The value is a byte string (which may contain encoded UTF8 text).
     * Required for source and optional filter for verifier/acceptor.
     * If they key algorithm is different than ::BSLX_COSESC_OPTION_TGT_ALG option,
     * the key will be used for the recipient layer, otherwise it will be used
     * for a single-layer message.
     */
    BSLX_COSESC_OPTION_KEY_ID,
    /** Optional recipient algorithm as an integer.
     * The value is a COSE algorithm code point (::BSLX_CoseMsg_Alg_e).
     * Optional for source and optional filter for verifier/acceptor.
     * When not present, the key itself must have an algorithm parameter.
     */
    BSLX_COSESC_OPTION_KEY_ALG,
    /** Content-layer algorithm as an integer.
     * The value is a COSE algorithm code point (::BSLX_CoseMsg_Alg_e).
     * Required for source and optional filter for verifier/acceptor.
     */
    BSLX_COSESC_OPTION_TGT_ALG,
    /** AAD Scope as raw encoded data.
     * The value is encoded CBOR interpreted as ::BSLX_CoseSc_AadScope_t.
     * Optional for source, optional exact-match for verifier/acceptor.
     */
    BSLX_COSESC_OPTION_AAD_SCOPE,
};

/// @brief From https://www.ietf.org/archive/id/draft-ietf-dtn-bpsec-cose-16.html#section-2.2
enum BSLX_CoseSC_Param_e
{
    BSLX_COSESC_PARAM_ADDL_PHDR = 3,
    BSLX_COSESC_PARAM_ADDL_UHDR = 4,
    BSLX_COSESC_PARAM_AAD_SCOPE = 5,
};

/// @brief From https://www.ietf.org/archive/id/draft-ietf-dtn-bpsec-cose-16.html#section-2.3
enum BSLX_CoseSC_Result_e
{
    BSLX_COSESC_RESULT_COSE_ENC0  = 16,
    BSLX_COSESC_RESULT_COSE_MAC0  = 17,
    BSLX_COSESC_RESULT_COSE_SIGN1 = 18,
    BSLX_COSESC_RESULT_COSE_ENC   = 96,
    BSLX_COSESC_RESULT_COSE_MAC   = 97,
    BSLX_COSESC_RESULT_COSE_SIGN  = 98,
};

/** @struct BSLX_CoseSc_AadScope_t
 * An internal representation of AAD Scope map, with keys sorted in
 * CBOR deterministic order and values as a bit mask of
 * ::BSLX_CoseSC_AAD_Flag_e flags.
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
M_BPTREE_DEF2(BSLX_CoseSc_AadScope, 4, int64_t, M_OPEXTEND(M_BASIC_OPLIST, CMP(API_6(BSL_CBOR_Compare_Int64))),
              uint64_t, M_BASIC_OPLIST)
// GCOV_EXCL_STOP
/// @endcond
// NOLINTEND

/// Flags for AAD Scope parameter
enum BSLX_CoseSC_AAD_Flag_e
{
    BSLX_COSESC_AAD_FLAG_METADATA = 0x1,
    BSLX_COSESC_AAD_FLAG_BTSD     = 0x2,
};

int BSLX_CoseSc_AadScope_Encode(QCBOREncodeContext *enc, const BSLX_CoseSc_AadScope_t *scope);

int BSLX_CoseSc_AadScope_Decode(QCBORDecodeContext *dec, BSLX_CoseSc_AadScope_t *scope);

/// Match signature ::BSL_SecCtx_Validate_f
bool BSLX_CoseSc_Validate(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper);

/// Match signature ::BSL_SecCtx_Execute_f
int BSLX_CoseSc_Execute(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                        BSL_SecOutcome_t *sec_outcome);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLX_COSECONTEXT_H_ */
