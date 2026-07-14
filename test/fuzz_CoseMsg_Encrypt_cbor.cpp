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
 * @ingroup fuzz_test
 * @brief Fuzz the COSE Context result decoding.
 */
#include "TestUtils.h"
#include <bsl/mock_bpa/MockBPA.h>
#include <bsl/cose_sc/CoseMsg.h>
#include <bsl/dynamic/CBOR.h>
#include <cinttypes>

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerInitialize(int *argc _U_, char ***argv _U_)
{
    BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL));
    mock_bpa_LogOpen();
    mock_bpa_LogSetLeastSeverity(LOG_CRIT);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int retval = 0;

    BSLX_CoseMsg_Encrypt_t msg;
    BSLX_CoseMsg_Encrypt_Init(&msg);

    {
        BSL_Data_t in_buf;
        BSL_Data_InitView(&in_buf, size, (BSL_DataPtr_t)data);
        int res = BSL_CBOR_Decode(&in_buf, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Encrypt_Decode, &msg);
        BSL_Data_Deinit(&in_buf);
        if (BSL_SUCCESS != res)
        {
            retval = -1;
        }
    }

    BSL_Data_t out_buf;
    BSL_Data_Init(&out_buf);
    if (!retval)
    {
        int res = BSL_CBOR_Encode_Twopass(&out_buf, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_Encrypt_Encode, &msg);
        if (BSL_SUCCESS != res)
        {
            retval = -1;
        }
    }

    if (!retval)
    {
        // output may be a subset
        // CBOR tags on input will not be carried
        if (size >= out_buf.len)
        {
            if (0 != memcmp(data, out_buf.ptr, out_buf.len))
            {
                retval = -1;
            }
        }
    }

    BSL_Data_Deinit(&out_buf);
    BSLX_CoseMsg_Encrypt_Deinit(&msg);

    return retval;
}
