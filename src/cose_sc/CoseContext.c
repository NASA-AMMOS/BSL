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
 * Implementation of the COSE context @cite draft-ietf-dtn-bpsec-cose.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>

#include "CoseContext.h"


bool BSLX_CoseSc_Validate(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    (void)lib;
    (void)bundle;
    (void)sec_oper;
    return true;
}

int BSLX_CoseSc_Execute(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                        BSL_SecOutcome_t *sec_outcome)
{
    (void)lib;
    (void)bundle;
    (void)sec_oper;
    (void)sec_outcome;
    return BSL_SUCCESS;
}
