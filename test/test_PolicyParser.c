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
 * @ingroup unit_test
 *
 * @brief Test the config reader of the Sample Policy Provider.
 */
#include "DefaultScUtils.h"

#include <bsl/sample_pp/PolicyParser.h>
#include <bsl/mock_bpa/MockBPA.h>

#include <fcntl.h>
#include <unistd.h>
#include <unity.h>

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
    policy = BSLP_PolicyProvider_New(1);
    TEST_ASSERT_NOT_NULL(policy);
}

void tearDown(void)
{
    BSLP_PolicyProvider_Destroy(policy);
    policy = NULL;
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Deinit(&LocalTestCtx));
}

static void AddTestRule(int64_t rule_id)
{
    BSLP_PolicyRule_t rule;
    BSLP_PolicyRule_InitFrom(&rule, rule_id, "existing", 2, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PRIMARY, BSL_POLICYACTION_NOTHING);
    BSLP_PolicyPredicate_t predicate;
    BSLP_PolicyPredicate_InitFrom(&predicate, BSL_POLICYLOCATION_CLOUT, "*:**", "*:**", "*:**");
    TEST_ASSERT_EQUAL_INT(BSL_SUCCESS, BSLP_PolicyProvider_AddRule(policy, &rule, &predicate));
}

static void LoadValidSc1(BSLP_PolicyParser_LoadMode_e mode)
{
    TEST_ASSERT_EQUAL_INT(BSL_SUCCESS, BSLP_PolicyParser_LoadFileWithMode("test_PolicyParser-data/validSC1.json", policy, mode));
}

TEST_CASE("test_PolicyParser-data/empty.json", 0)
TEST_CASE("test_PolicyParser-data/validSC1.json", 1)
TEST_CASE("test_PolicyParser-data/validSC2.json", 1)
TEST_CASE("test_PolicyParser-data/validSC3-parms-long.json", 1)
TEST_CASE("test_PolicyParser-data/validSC3-parms-short.json", 1)
void test_PolicyParser_ReadConfigValid(const char *filename, int rule_count)
{
    int infd = open(filename, O_RDONLY);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, infd);
    TEST_ASSERT_EQUAL_INT(BSL_SUCCESS, BSLP_PolicyParser_LoadFd(infd, policy));
    TEST_ASSERT_EQUAL_INT(0, close(infd));

    TEST_ASSERT_EQUAL_size_t(rule_count, BSLP_PolicyProvider_RuleCount(policy));
}

TEST_CASE("test_PolicyParser-data/unknownSC-99.json")
void test_PolicyParser_ReadConfigInvalid(const char *filename)
{
    int infd = open(filename, O_RDONLY);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, infd);
    TEST_ASSERT_NOT_EQUAL_INT(BSL_SUCCESS, BSLP_PolicyParser_LoadFd(infd, policy));
    TEST_ASSERT_EQUAL_INT(0, close(infd));

    TEST_ASSERT_EQUAL_size_t(0, BSLP_PolicyProvider_RuleCount(policy));
}

void test_PolicyParser_ReplacesExistingRuleId(void)
{
    AddTestRule(1);
    LoadValidSc1(BSLP_POLICY_LOAD_ADDITIVE);

    TEST_ASSERT_EQUAL_size_t(1, BSLP_PolicyProvider_RuleCount(policy));
    const BSLP_PolicyRule_t *rule = BSLP_PolicyProvider_GetRuleById(policy, 1);
    TEST_ASSERT_NOT_NULL(rule);
    TEST_ASSERT_EQUAL_INT(BSL_SECROLE_SOURCE, rule->role);
    TEST_ASSERT_EQUAL_INT(BSL_SECBLOCKTYPE_BIB, rule->sec_block_type);
    TEST_ASSERT_EQUAL_INT(1, rule->context_id);
    TEST_ASSERT_EQUAL_UINT64(BSL_BLOCK_TYPE_PAYLOAD, rule->target_block_type);
}

void test_PolicyParser_AdditiveRetainsUnspecifiedRules(void)
{
    AddTestRule(99);
    TEST_ASSERT_EQUAL_INT(BSL_SUCCESS, BSLP_PolicyParser_LoadFile("test_PolicyParser-data/validSC1.json", policy));

    TEST_ASSERT_EQUAL_size_t(2, BSLP_PolicyProvider_RuleCount(policy));
    TEST_ASSERT_NOT_NULL(BSLP_PolicyProvider_GetRuleById(policy, 1));
    TEST_ASSERT_NOT_NULL(BSLP_PolicyProvider_GetRuleById(policy, 99));
}

void test_PolicyParser_CleanRemovesExistingRulesBeforeLoad(void)
{
    AddTestRule(99);
    LoadValidSc1(BSLP_POLICY_LOAD_CLEAN);

    TEST_ASSERT_EQUAL_size_t(1, BSLP_PolicyProvider_RuleCount(policy));
    TEST_ASSERT_NOT_NULL(BSLP_PolicyProvider_GetRuleById(policy, 1));
    TEST_ASSERT_NULL(BSLP_PolicyProvider_GetRuleById(policy, 99));
}

void test_PolicyParser_FullSpecRemovesUnspecifiedRules(void)
{
    AddTestRule(1);
    AddTestRule(99);
    LoadValidSc1(BSLP_POLICY_LOAD_FULL_SPEC);

    TEST_ASSERT_EQUAL_size_t(1, BSLP_PolicyProvider_RuleCount(policy));
    const BSLP_PolicyRule_t *rule = BSLP_PolicyProvider_GetRuleById(policy, 1);
    TEST_ASSERT_NOT_NULL(rule);
    TEST_ASSERT_EQUAL_INT(BSL_SECROLE_SOURCE, rule->role);
    TEST_ASSERT_NULL(BSLP_PolicyProvider_GetRuleById(policy, 99));
}
