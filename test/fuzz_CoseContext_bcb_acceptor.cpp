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
 * @brief Fuzz the COSE Context secop processing as a loose acceptor.
 */
#include "TestUtils.h"

#include <bsl/crypto/KeyLoader.h>
#include <bsl/sample_pp/PolicyParser.h>
#include <bsl/mock_bpa/ctr.h>
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

/// Agent for all inputs
static MockBPA_Agent_t agent;
/// Policy for #agent
static BSLP_PolicyProvider_t *policy;

extern "C" int LLVMFuzzerInitialize(int *argc _U_, char ***argv _U_)
{
    if (BSL_SUCCESS != BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(&agent)))
    {
        BSL_LOG_CRIT("Failed to initialize host descriptors");
        return 2;
    }
    mock_bpa_LogOpen();
    mock_bpa_LogSetLeastSeverity(LOG_CRIT);

    MockBPA_KeyStore_Init();
    if (BSL_SUCCESS != BSL_Crypto_KeyLoader_LoadFile("../mock-bpa-test/data/cose-sc/keyset-1.cbor"))
    {
        BSL_LOG_CRIT("Failed to load keystore");
        return 2;
    }

    if (BSL_SUCCESS != MockBPA_Agent_Init(&agent, &policy))
    {
        BSL_LOG_CRIT("Failed to initialize mock BPA");
        return 2;
    }
    if (BSL_SUCCESS != BSLP_PolicyParser_LoadFile("../mock-bpa-test/data/cose-sc/policy-any-bcb-accept.json", policy))
    {
        BSL_LOG_CRIT("Failed to load policy");
        return 2;
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int retval = 0;

    mock_bpa_ctr_t item;
    mock_bpa_ctr_init(&item);

    BSL_Data_InitView(&item.encoded, size, (BSL_DataPtr_t)data);

    if (mock_bpa_ctr_decode(&item))
    {
        BSL_LOG_ERR("failed to decode bundle");
        retval = -1;
    }

    if (!retval)
    {
        // interaction point aligns with policy config
        if (MockBPA_Agent_process(&agent, &agent.appout, &item))
        {
            BSL_LOG_ERR("failed security processing");
            retval = 3;
        }
    }

    mock_bpa_ctr_deinit(&item);
    return retval;
}
