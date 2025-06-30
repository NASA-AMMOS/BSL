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

#include "backend/DeprecatedLibContext.h"
#include "bsl_mock_bpa.h"
#include "backend/DynBundleContext.h"
#include "Logging.h"
#include <DeprecatedTypes.h>
#include <TypeDefintions.h>
#include <inttypes.h>
#include <unity.h>

// Note: These tests still work, but are deprecates since relevants structs have been renamed and moved.

static BSL_LibCtx_t    bsl;
static BSL_BundleCtx_t bundle;
static int             inspect_count;

// Fits the signature of BSL_PolicyInspect_f
static int mock_pp_inspect(BSL_LibCtx_t *lib, BSL_PolicyLocation_e location, const BSL_BundleCtx_t *bundle,
                           BSL_PolicyActionDeprecatedIList_t acts, void *user_data _U_)
{
    uint64_t blk_type;
    if (BSL_BundleContext_GetBlockMetadata(bundle, 2, &blk_type, NULL, NULL, NULL))
    {
        BSL_LOG_DEBUG("inspect missing block #2");
        return 1;
    }
    BSL_LOG_DEBUG("inspect! at loc %d, block type %" PRIu64, location, blk_type);
    inspect_count += 1;

    BSL_LibCtx_AllocPolicyActionDeprecatedList(lib, acts, 1);
    BSL_PolicyActionDeprecated_t *act = BSL_PolicyActionDeprecatedIList_front(acts);
    BSL_LOG_DEBUG("ops in action %zu", BSL_SecOperList_size(act->sec_oper_list));

    return 0;
}

void suiteSetUp(void)
{
    BSL_openlog();
    assert(0 == bsl_mock_bpa_init());
}

int suiteTearDown(int failures)
{
    bsl_mock_bpa_deinit();
    BSL_closelog();
    return failures;
}

void setUp(void)
{
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Init(&bsl));
    {
        BSL_PolicyDesc_t desc = {
            .inspect = &mock_pp_inspect,
        };
        TEST_ASSERT_EQUAL(0, BSL_LibCtx_AddPolicyProvider(&bsl, desc));
    }

    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_Init(&bundle, &bsl));

    inspect_count = 0;
}

void tearDown(void)
{
    BSL_BundleCtx_Deinit(&bundle);
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Deinit(&bsl));
}

static BSL_BundleBlock_t add_dummy_block(void)
{
    static const uint8_t btsd[] = { 0x01, 0x02, 0x03 };

    BSL_BundleBlock_t info = {
        .blk_type = 10,
        .blk_num  = 2,
        .flags    = 0x34,
        .crc_type = 1,
    };
    BSL_Data_InitView(&info.btsd, sizeof(btsd) / sizeof(uint8_t), (BSL_DataPtr_t)btsd);
    BSL_LOG_DEBUG("add block type %" PRIu64, info.blk_type);
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_AddBlock(&bundle, info));

    return info;
}

void test_bundle_ctx_one_block(void)
{
    add_dummy_block();
    TEST_ASSERT_EQUAL(0, inspect_count);

    BSL_PolicyActionDeprecatedIList_t acts;
    BSL_PolicyActionDeprecatedIList_init(acts);
    TEST_ASSERT_EQUAL(0, BSL_PolicyRegistry_Inspect(&bsl, BSL_POLICYLOCATION_APPIN, &bundle, acts));
    TEST_ASSERT_EQUAL(1, inspect_count);

    BSL_LibCtx_FreePolicyActionDeprecatedList(&bsl, acts);
    BSL_PolicyActionDeprecatedIList_clear(acts);
}
