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
#ifndef _BSL_TESTUTILS_H_
#define _BSL_TESTUTILS_H_

#include <m-string.h>

#include <bsl/dynamic/PublicInterfaceImpl.h>
#include <bsl/dynamic/SecOperation.h>
#include <bsl/dynamic/IdValPair.h>
#include <bsl/dynamic/SecurityActionSet.h>
#include <bsl/mock_bpa/ctr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_CASE(...)
#define TEST_RANGE(...)
#define TEST_MATRIX(...)

typedef struct BSL_TestContext_s
{
    BSL_LibCtx_t   bsl;
    mock_bpa_ctr_t mock_bpa_ctr;
    uint64_t       key_id;
} BSL_TestContext_t;

int BSL_TestContext_Init(BSL_TestContext_t *ctx);
int BSL_TestContext_Deinit(BSL_TestContext_t *ctx);

/** Load a full bundle state into a test context.
 *
 * @param[in,out] test_ctx The context to copy and decode into.
 * @param[in] cborhex The input bundle in base16.
 */
int BSL_TestUtils_LoadBundleFromCBOR(BSL_TestContext_t *test_ctx, const char *cborhex);

/** Encode a bundle state to CBOR.
 *
 * @param[in,out] test_ctx The context to encode.
 */
int BSL_TestUtils_EncodeBundleToCBOR(BSL_TestContext_t *test_ctx);

BSL_HostEIDPattern_t BSL_TestUtils_GetEidPatternFromText(const char *text);

void BSL_TestUtils_PrintHexToBuffer(const char *message, uint8_t *buff, size_t bufflen);

/** Compare an expected base-16 encoded byte string with an actual value.
 *
 * @param expected_hex The expected value in base-16 as a null-terminated string.
 * @param encoded_val The value to check.
 * @return True if they are byte-wise identical.
 */
bool BSL_TestUtils_IsB16StrEqualTo(const char *expected_hex, BSL_Data_t encoded_val);

/** Decode base16 text form.
 *
 * @param[out] output The output buffer, which will be sized to its data.
 * @param[in] input The input buffer to read, which must be null terminated.
 * Whitespace in the input must have already been removed with strip_space().
 * @return Zero upon success.
 */
int BSL_TestUtils_DecodeBase16_cstr(BSL_Data_t *output, const char *input);

/**
 * Modify bundle's source eid, destination eid, and report-to eid.
 * @warning This violates the BPv7 constraint of an immutable primary block,
 * and is for testing only!
 *
 * @param[in, out] input_bundle bundle to modify
 * @param[in] src_eid EID to set bundle source EID to. Set to NULL if bundle source EID should remain unchanged.
 * @param[in] dest_eid EID to set bundle destination EID to. Set to NULL if bundle destination EID should remain
 * unchanged.
 * @param[in] report_to_eid EID to set bundle report-to EID to. Set to NULL if bundle report-to EID should remain
 * unchanged.
 */
int BSL_TestUtils_ModifyEIDs(BSL_BundleRef_t *input_bundle, const char *src_eid, const char *dest_eid,
                             const char *report_to_eid);

/** Initialize a flat-buffer reader object.
 */
BSL_SeqReader_t *BSL_TestUtils_FlatReader(const void *buf, size_t bufsize);

/** Initialize a flat-buffer reader object.
 */
BSL_SeqWriter_t *BSL_TestUtils_FlatWriter(void **buf, size_t *bufsize);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _BSL_TESTUTILS_H_
