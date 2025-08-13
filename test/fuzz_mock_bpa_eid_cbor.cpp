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
#include <mock_bpa/BPSecLib_MockBPA.h>
#include "bsl_test_utils.h"
#include <cinttypes>

#define EXPECT_EQ(expect, got) if ((expect) != (got)) { BSL_LOG_ERR("EXPECT failure"); }

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerInitialize(int *argc _U_, char ***argv _U_)
{
    BSL_openlog();
    bsl_mock_bpa_init();
    return 0;
}
/* No cleanup:
    bsl_mock_bpa_deinit();
    BSL_closelog();
*/

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int retval = 0;

    BSL_HostEID_t eid;
    BSL_HostEID_Init(&eid);
    {
        QCBORDecodeContext decoder;
        QCBORDecode_Init(&decoder, (UsefulBufC) { data, size }, QCBOR_DECODE_MODE_NORMAL);
        int res_eid = bsl_mock_decode_eid(&decoder, &eid);
        int res_cbor = QCBORDecode_Finish(&decoder);
        if (res_eid || (res_cbor != QCBOR_SUCCESS))
        {
            retval = -1;
        }
    }

    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    if (!retval)
    {
        QCBOREncodeContext encoder;
        size_t             needlen;

        QCBOREncode_Init(&encoder, SizeCalculateUsefulBuf);
        EXPECT_EQ(0, bsl_mock_encode_eid(&encoder, &eid));
        assert(QCBOR_SUCCESS == QCBOREncode_FinishGetSize(&encoder, &needlen));

        EXPECT_EQ(0, BSL_Data_Resize(&out_data, needlen));
        QCBOREncode_Init(&encoder, (UsefulBuf) { out_data.ptr, out_data.len });
        EXPECT_EQ(0, bsl_mock_encode_eid(&encoder, &eid));

        UsefulBufC out;
        EXPECT_EQ(QCBOR_SUCCESS, QCBOREncode_Finish(&encoder, &out));
    }

    if (!retval)
    {
        // output may be a subset
        if (size != out_data.len)
        {
            // CBOR tags on input will not be carried
            // BSL_LOG_ERR("Bad re-encoding size, expect %" PRIu64 " got %" PRIu64 ", for scheme %" PRIu64, size, out_data.len, ((bsl_mock_eid_t*)eid.handle)->scheme);
            retval = -1;
        }
        if (0 != memcmp(data, out_data.ptr, out_data.len))
        {
            retval = -1;
        }
    }

    BSL_Data_Deinit(&out_data);
    BSL_HostEID_Deinit(&eid);
    return retval;
}
