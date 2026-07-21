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

#include "bsl/BPSecLib_Private.h"
#include "bsl/BPSecLib_Public.h"

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
    BSLX_COSESC_OPTION_KEY_ID = 3000,
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
     * The value is encoded CBOR interpreted as ::BSLX_CoseSc_AadScope_t,
     * and can use the BSLX_CoseSc_SetAadScope() helper in policy providers.
     * Optional for source, optional exact-match for verifier/acceptor.
     */
    BSLX_COSESC_OPTION_AAD_SCOPE,
    /** An option to use the key telemetry counter
     * (number of security operations performed) as the basis of a unique
     * IV or Partial IV for encryption.
     * The value is an offset (as @c int64_t) to add to the counter which
     * is then converted to a byte string in network byte order.
     * When used as IV this is padded to the needed length, when used as
     * Partial IV it is not padded.
     * Optional for source and unused for verifier/acceptor.
     */
    BSLX_COSESC_OPTION_IV_COUNTER_OFFSET,
    /** An option to define a Base IV outside a COSE key.
     * The value is a byte string used in the same way that RFC 9052
     * defines the Base IV of a key.
     * When present, this base will not be visible in the messaging.
     * Optional for source and unused for verifier/acceptor.
     */
    BSLX_COSESC_OPTION_IV_BASE,
    /** An option to select a salt length for KDF sources.
     * The value is a length in bytes (as @c int64_t) to generate a salt.
     * Optional for source and unused for verifier/acceptor.
     * When not present, the default salt length for the KDF algorithm
     * will be used.
     */
    BSLX_COSESC_OPTION_SALT_LENGTH,
    /** An option to use the key telemetry counter
     * (number of security operations performed) as the basis of a unique
     * salt for key derivation.
     * The value is an offset (as @c int64_t) to add to the counter which
     * is then converted to a byte string in network byte order.
     * When used as a salt this is not padded.
     * Optional for source and unused for verifier/acceptor.
     */
    BSLX_COSESC_OPTION_SALT_COUNTER_OFFSET,
    /** An option to define a base salt value (similar in function to a Base IV).
     * The value is a byte string used to determine the full salt length
     * and XOR-ed with the salt counter.
     * When present, this base will not be visible in the messaging.
     * Optional for source and unused for verifier/acceptor.
     */
    BSLX_COSESC_OPTION_SALT_BASE,
};

/// @brief From https://www.ietf.org/archive/id/draft-ietf-dtn-bpsec-cose-16.html#section-2.2
enum BSLX_CoseSC_Param_e
{
    /// Additional Protected headers
    BSLX_COSESC_PARAM_ADDL_PHDR = 3,
    /// Additional Unprotected headers
    BSLX_COSESC_PARAM_ADDL_UHDR = 4,
    /// AAD Scope map
    BSLX_COSESC_PARAM_AAD_SCOPE = 5,
};

/// @brief From https://www.ietf.org/archive/id/draft-ietf-dtn-bpsec-cose-16.html#section-2.3
enum BSLX_CoseSC_Result_e
{
    BSLX_COSESC_RESULT_COSE_ENCRYPT0 = 16,
    BSLX_COSESC_RESULT_COSE_MAC0     = 17,
    BSLX_COSESC_RESULT_COSE_SIGN1    = 18,
    BSLX_COSESC_RESULT_COSE_ENCRYPT  = 96,
    BSLX_COSESC_RESULT_COSE_MAC      = 97,
    BSLX_COSESC_RESULT_COSE_SIGN     = 98,
};

/// Special keys for AAD Scope parameter
enum BSLX_CoseSC_AadScope_Special_e
{
    /// Reference the security target block
    BSLX_COSESC_AADSCOPE_SPECIAL_TARGET = -1,
    /// Reference the parent security block
    BSLX_COSESC_AADSCOPE_SPECIAL_SECURITY = -2,
};

/// Flags for AAD Scope parameter
enum BSLX_CoseSC_AadScope_Flag_e
{
    /// Include block header items in AAD
    BSLX_COSESC_AADSCOPE_FLAG_METADATA = 0x1,
    /// Include BTSD in AAD
    BSLX_COSESC_AADSCOPE_FLAG_BTSD = 0x2,
};

/** Native C structure for each item of COSE Context AAD Scope.
 */
typedef struct
{
    /// Block number or special key from ::BSLX_CoseSC_AadScope_Special_e
    int64_t key;
    /** Choice of flags from ::BSLX_CoseSC_AAD_Flag_e.
     * This type is compatible with ::BSL_IdValPair_t storage.
     */
    int64_t flags;
} BSLX_CoseSc_AadScope_Item_t;

/** Utility to set the ::BSLX_COSESC_OPTION_AAD_SCOPE option without exposing
 * the encoding internals.
 *
 * @param[in,out] option Pointer to the option to set the AAD Scope on.
 * @param[in] list Pointer to an array of integer values, each
 * subsequent pair of values is interpreted as a (key, value) in the scope map.
 * The order of keys in this form is not significant.
 * @param count The number of @b pairs of values in the @c list array.
 * @return BSL_SUCCESS if successful.
 */
int BSLX_CoseSc_SetAadScope(BSL_IdValPair_t *option, const BSLX_CoseSc_AadScope_Item_t *list, size_t count);

/// Match signature ::BSL_SecCtx_Validate_f
bool BSLX_CoseSc_Validate(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper);

/// Match signature ::BSL_SecCtx_Execute_f
int BSLX_CoseSc_Execute(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLX_COSECONTEXT_H_ */
