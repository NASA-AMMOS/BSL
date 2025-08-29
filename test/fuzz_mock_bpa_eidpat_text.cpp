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
#include <mock_bpa/MockBPA.h>
#include "bsl_test_utils.h"
#include <m-bstring.h>
#include <m-string.h>
#include <cinttypes>

#define EXPECT_EQ(expect, got)          \
    if ((expect) != (got))              \
    {                                   \
        BSL_LOG_CRIT("EXPECT failure"); \
    }

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerInitialize(int *argc _U_, char ***argv _U_)
{
    BSL_openlog();
    BSL_LogSetLeastSeverity(LOG_CRIT);
    BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL));
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int retval = 0;

    m_bstring_t buf;
    m_bstring_init(buf);
    if (size)
    {
        m_bstring_push_back_bytes(buf, size, data);
    }
    m_bstring_push_back(buf, '\0');

    size_t      buf_size = m_bstring_size(buf);
    const char *buf_ptr  = (const char *)m_bstring_view(buf, 0, buf_size);

    if (!m_str1ng_utf8_valid_str_p(buf_ptr))
    {
        m_bstring_clear(buf);
        return -1;
    }

    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    int res_dec = BSL_HostEIDPattern_DecodeFromText(&pat, buf_ptr);
    if (res_dec)
    {
        retval = -1;
    }

    BSL_HostEIDPattern_Deinit(&pat);
    m_bstring_clear(buf);
    return retval;
}
