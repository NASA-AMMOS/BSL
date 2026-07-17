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
 * @brief Fuzz the simplified JWK file decoding.
 */
#include "TestUtils.h"

#include <bsl/crypto/CryptoInterface.h>
#include <bsl/mock_bpa/KeyStore.h>
#include <bsl/mock_bpa/MockBPA.h>

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
    BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL));
    mock_bpa_LogOpen();
    mock_bpa_LogSetLeastSeverity(LOG_CRIT);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int retval = 0;
    MockBPA_KeyStore_Init();

    FILE  *tmp = tmpfile();
    size_t got = fwrite(data, size, 1, tmp);
    if (got != size)
    {
        retval = -1;
    }
    fflush(tmp);
    fseek(tmp, 0, SEEK_SET);

    if (!retval)
    {
        int infd = fileno(tmp);
        if (MockBPA_KeyStore_LoadJwk(infd))
        {
            retval = -1;
        }
    }

    fclose(tmp);
    MockBPA_KeyStore_Deinit();
    return retval;
}
