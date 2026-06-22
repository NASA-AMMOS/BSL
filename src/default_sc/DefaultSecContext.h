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
 * @ingroup default_sc
 * Header for the implementation of an example default security context (RFC 9173).
 */

#ifndef BSLX_SECCTXERR_H_
#define BSLX_SECCTXERR_H_

#include <BPSecLib_Private.h>
#include <BPSecLib_Public.h>
// for option values
#include <default_sc/rfc9173.h>

/// Internal BIB option enumerations
enum BSLX_BIB_Options_e
{

    /// @brief Used to pass in a key id found in the key registry.
    BSLX_BIB_OPT_KEY_ID = 1000,
    /// @brief A uint value 0 to skip key wrap, else use key wrap
    BSLX_BIB_OPT_USE_KEY_WRAP,
    /** Manually control the wrapped key.
     * @warning This should only be used for testing.
     */
    BSLX_BIB_OPT_WRAPPED_KEY,

    /// @brief A uint value from the choices ::rfc9173_bib_sha_variantid_e
    BSLX_BIB_OPT_SHA_VARIANT,
    /// @brief A uint value from the choices ::rfc9173_bib_integ_scope_flag_ids_e
    BSLX_BIB_OPT_SCOPE,
};

/// Match signature ::BSL_SecCtx_Execute_f
int BSLX_BIB_Execute(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                     BSL_SecOutcome_t *sec_outcome);

/// Match signature ::BSL_SecCtx_Validate_f
bool BSLX_BIB_Validate(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper);

/// Internal BCB option enumerations
enum BSLX_BCB_Options_e
{

    /// @brief Used to pass in a key id found in the key registry.
    BSLX_BCB_OPT_KEY_ID = 2000,
    /// @brief A uint value 0 to skip key wrap, else use key wrap
    BSLX_BCB_OPT_USE_KEY_WRAP,
    /** Manually control the wrapped key.
     * @warning This should only be used for testing.
     */
    BSLX_BCB_OPT_WRAPPED_KEY,
    /** Manually control the IV.
     * @warning This should only be used for testing.
     */
    BSLX_BCB_OPT_IV,

    /// @brief A uint value from the choices ::rfc9173_bcb_aes_variant_e
    BSLX_BCB_OPT_AES_VARIANT,
    /// @brief A uint value from the choices ::rfc9173_bcb_aad_scope_flag_ids_e
    BSLX_BCB_OPT_SCOPE,
};

/// Match signature ::BSL_SecCtx_Execute_f
int BSLX_BCB_Execute(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                     BSL_SecOutcome_t *sec_outcome);

/// Match signature ::BSL_SecCtx_Validate_f
bool BSLX_BCB_Validate(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper);

#endif /* BSLX_SECCTXERR_H_ */
