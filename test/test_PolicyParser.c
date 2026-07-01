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
 * @ingroup unit-tests
 *
 * @brief Test the config reader of the Sample Policy Provider.
 */
#include <unity.h>

#include <BPSecLib_Private.h>

#include <mock_bpa/MockBPA.h>
#include "DefaultScUtils.h"

#include <policy_provider/PolicyParser.h>

static BSL_TestContext_t      LocalTestCtx;
static BSLP_PolicyProvider_t *policy;

void suiteSetUp(void)
{
    TEST_ASSERT_EQUAL_INT(0, BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL)));
    mock_bpa_LogOpen();
}

int suiteTearDown(int failures)
{
    mock_bpa_LogClose();
    BSL_HostDescriptors_Clear();
    return failures;
}

void setUp(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:2.1", 1);
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Init(&LocalTestCtx));
    policy = BSLP_PolicyProvider_Init(1);
    TEST_ASSERT_NOT_NULL(policy);
}

void tearDown(void)
{
    BSLP_PolicyProvider_Destroy(policy);
    policy = NULL;
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Deinit(&LocalTestCtx));
}

void test_PolicyParser_ReadConfigEmpty(void)
{
    TEST_ASSERT_EQUAL_INT(BSL_SUCCESS, BSLP_PolicyParser_FromJSON("test_PolicyParser-data/empty.json", policy));
    TEST_ASSERT_EQUAL_size_t(0, BSLP_PolicyRuleList_size(policy->rules));
    TEST_ASSERT_EQUAL_size_t(0, BSLP_PolicyPredicateList_size(policy->predicates));
}

TEST_CASE("test_PolicyParser-data/validSC1.json", 1)
TEST_CASE("test_PolicyParser-data/validSC2.json", 2)
TEST_CASE("test_PolicyParser-data/validSC3-parms-long.json", 3)
TEST_CASE("test_PolicyParser-data/validSC3-parms-short.json", 3)
/** Read a valid configuration for a single context.
 */
void test_PolicyParser_ReadConfigValid(const char *filename, int context_id)
{
    TEST_ASSERT_EQUAL_INT(BSL_SUCCESS, BSLP_PolicyParser_FromJSON(filename, policy));

    TEST_ASSERT_EQUAL_size_t(1, BSLP_PolicyRuleList_size(policy->rules));
    TEST_ASSERT_EQUAL_size_t(1, BSLP_PolicyPredicateList_size(policy->predicates));

    const BSLP_PolicyRule_t *rule = BSLP_PolicyRulePtr_cref(*BSLP_PolicyRuleList_front(policy->rules));
    TEST_ASSERT_EQUAL_INT(context_id, rule->context_id);
}

TEST_CASE("test_PolicyParser-data/unknownSC-99.json")
void test_PolicyParser_ReadConfigInvalid(const char *filename)
{
    TEST_ASSERT_NOT_EQUAL_INT(BSL_SUCCESS, BSLP_PolicyParser_FromJSON(filename, policy));
    TEST_ASSERT_EQUAL_size_t(0, BSLP_PolicyRuleList_size(policy->rules));
    TEST_ASSERT_EQUAL_size_t(0, BSLP_PolicyPredicateList_size(policy->predicates));
}
