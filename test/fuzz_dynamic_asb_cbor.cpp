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
#include <BPSecLib_Private.h>
#include "bsl_test_utils.h"
#include <cinttypes>

#define EXPECT_EQ(expect, got)         \
    if ((expect) != (got))             \
    {                                  \
        BSL_LOG_CRIT("EXPECT failure"); \
    }

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerInitialize(int *argc _U_, char ***argv _U_)
{
    BSL_openlog();
    BSL_LogSetLeastSeverity(LOG_CRIT);
    bsl_mock_bpa_agent_init();
    return 0;
}
/* No cleanup:
    bsl_mock_bpa_agent_deinit();
    BSL_closelog();
*/

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int retval = 0;

    BSL_AbsSecBlock_t *asb = (BSL_AbsSecBlock_t *)BSL_MALLOC(BSL_AbsSecBlock_Sizeof());
    BSL_AbsSecBlock_InitEmpty(asb);

    {
        BSL_Data_t buf;
        BSL_Data_InitView(&buf, size, (BSL_DataPtr_t)data);
        int res = BSL_AbsSecBlock_DecodeFromCBOR(asb, &buf);
        BSL_Data_Deinit(&buf);
        if (res)
        {
            retval = -1;
        }
    }

    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    if (!retval)
    {
        ssize_t needlen = BSL_AbsSecBlock_EncodeToCBOR(asb, SizeCalculateUsefulBuf);
        assert(needlen > 0);

        EXPECT_EQ(0, BSL_Data_Resize(&out_data, (size_t)needlen));
        ssize_t usedlen = BSL_AbsSecBlock_EncodeToCBOR(asb, (UsefulBuf) { out_data.ptr, out_data.len });
        EXPECT_EQ(needlen, usedlen);
    }

    if (!retval)
    {
        // output may be a subset
        // CBOR tags on input will not be carried
        if (size >= out_data.len)
        {
            if (0 != memcmp(data, out_data.ptr, out_data.len))
            {
                retval = -1;
            }
        }
    }

    BSL_Data_Deinit(&out_data);
    BSL_AbsSecBlock_Deinit(asb);
    BSL_FREE(asb);

    return retval;
}
