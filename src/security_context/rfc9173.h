/*
 * Copyright (c) 2025 The Johns Hopkins University Applied Physics
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
 * Contains constants as defined in IETF RFC 9173 (Default Security Context for BPSec)
 * @ingroup example_security_context
 */

#ifndef BSLB_RFC9173_H_
#define BSLB_RFC9173_H_

/// @brief https://www.rfc-editor.org/rfc/rfc9173.html#name-security-context-identifier
enum rfc9173_secctx_id_e
{
    RFC9173_CONTEXTID_BIB_HMAC_SHA2 = 1,
    RFC9173_CONTEXTID_BCB_AES_GCM   = 2
};

/// @brief https://www.rfc-editor.org/rfc/rfc9173.html#name-sha-variant-parameter-value
enum rfc9173_bib_sha_variantid_e
{
    RFC9173_BIB_SHA_HMAC256 = 5,
    RFC9173_BIB_SHA_HMAC384 = 6,
    RFC9173_BIB_SHA_HMAC512 = 7,
};

/// @brief https://www.rfc-editor.org/rfc/rfc9173.html#name-bib-hmac-sha2-security-cont
enum rfc9173_bib_paramid_e
{
    RFC9173_BIB_PARAMID_SHA_VARIANT      = 1,
    RFC9173_BIB_PARAMID_WRAPPED_KEY      = 2,
    RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG = 3
};

/// @brief https://www.rfc-editor.org/rfc/rfc9173.html#name-results
enum rfc9173_bib_resultid_e
{
    RFC9173_BIB_RESULTID_HMAC = 1
};

/// @brief https://www.rfc-editor.org/rfc/rfc9173.html#table-9
enum rfc9173_bib_integ_scope_flag_ids_e
{
    RFC9173_BIB_INTEGSCOPEFLAG_INC_PRIM       = 1,
    RFC9173_BIB_INTEGSCOPEFLAG_INC_TARGET_HDR = 2,
    RFC9173_BIB_INTEGSCOPEFLAG_INC_SEC_HDR    = 4
};

/// @brief https://www.rfc-editor.org/rfc/rfc9173.html#section-4.3.2
typedef enum
{
    RFC9173_BCB_AES_VARIANT_A128GCM = 1,

    // Default value
    RFC9173_BCB_AES_VARIANT_A256GCM = 3
} rfc9173_bcb_aes_variant_e;

enum rfc9173_bcb_secparam_ids_e
{
    RFC9173_BCB_SECPARAM_IV = 1,

    // Note, default value is 3 (see above enum.)
    RFC9173_BCB_SECPARAM_AESVARIANT = 2,
    RFC9173_BCB_SECPARAM_WRAPPEDKEY = 3,

    // Note, default value is 7
    RFC9173_BCB_SECPARAM_AADSCOPE = 4
};

#define RFC9173_BCB_DEFAULT_IV_LEN (12)

/// @brief https://www.rfc-editor.org/rfc/rfc9173.html#section-4.4.2
enum rfc9173_bcb_result_ids_e
{
    /// https://www.rfc-editor.org/rfc/rfc9173.html#name-bcb-aes-gcm-security-result
    RFC9173_BCB_RESULTID_AUTHTAG = 1
};

/// @brief https://www.rfc-editor.org/rfc/rfc9173.html#name-bpsec-bcb-aes-gcm-aad-scope
enum rfc9173_bcb_aad_scope_flag_ids_e
{
    RFC9173_BCB_AADSCOPEFLAGID_INC_PRIM_BLOCK      = 1,
    RFC9173_BCB_AADSCOPEFLAGID_INC_TARGET_HEADER   = 2,
    RFC9173_BCB_AADSCOPEFLAGID_INC_SECURITY_HEADER = 4,
};

#endif /* BSLB_RFC9173_H_ */
