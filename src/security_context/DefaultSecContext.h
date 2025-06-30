/*
 * Copyright (c) 2024 The Johns Hopkins University Applied Physics
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
 * Header for the implementation of an example default security context (RFC 9173).
 * @ingroup example_security_context
 */

#ifndef BSLX_SECCTXERR_H_
#define BSLX_SECCTXERR_H_

#include <BPSecLib.h>

enum BSLX_SecCtxErr_s
{
    BSLX_SECCTXERR_ERR_NONE = 0,

    /// Catch-all for any other kind of error
    BSLX_SECCTXERR_ERR_MISC,

    /// Indicates functionality not implemented and cannot be accomplished
    BSLX_SECCTXERR_ERR_UNIMPLEMENTED,

    /// Indicates the bundle block is malformed and cannot be processed per the spec
    BSLX_SECCTXERR_ERR_DATA_INTEGRITY,

    /// Indicates an error with CBOR encoding
    BSLX_SECCTXERR_ERR_CBOR_ENCODING,

    /// Indicates an error with CBOR decoding
    BSLX_SECCTXERR_ERR_CBOR_DECODING,

    /// Indicates an error with computing and producing an HMAC
    BSLX_SECCTXERR_ERR_HMAC_GEN,

    /// @brief  Indicates that the security operation failed
    BSLX_SECCTXERR_ERR_HMAC_AUTH_FAILURE
};

int BSLX_ExecuteBCB(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper,
                    BSL_SecOutcome_t *sec_outcome);


int BSLX_ExecuteBIB(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper,
                    BSL_SecOutcome_t *sec_outcome);

bool BSLX_ValidateBIB(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper);

bool BSLX_ValidateBCB(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper);

#endif /* BSLX_SECCTXERR_H_ */
