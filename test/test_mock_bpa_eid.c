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
#include <HostBPA.h>
#include <bsl_mock_bpa.h>
#include <bsl_mock_bpa_eid.h>
#include <Logging.h>
#include <unity.h>

// allow parameterized cases
#define TEST_CASE(...)

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

TEST_CASE("ipn:0.0", 0, 0, 0)
TEST_CASE("ipn:0.0.0", 0, 0, 0)
TEST_CASE("ipn:50.10", 0, 50, 10)
TEST_CASE("ipn:1.2.3", 1, 2, 3)
void test_BSL_HostEID_DecodeFromText_ipn(const char *text, uint64_t auth_num, uint64_t node_num, uint64_t svc_num)
{
    BSL_HostEID_t eid;
    BSL_HostEID_Init(&eid);
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&eid, text));
    TEST_ASSERT_NOT_NULL(eid.handle);
    const bsl_mock_eid_t *obj = eid.handle;
    TEST_ASSERT_EQUAL_INT(BSL_MOCK_EID_IPN, obj->scheme);
    TEST_ASSERT_EQUAL_INT_MESSAGE(auth_num, obj->ssp.as_ipn.auth_num, "auth form");
    TEST_ASSERT_EQUAL_INT_MESSAGE(node_num, obj->ssp.as_ipn.node_num, "node form");
    TEST_ASSERT_EQUAL_INT_MESSAGE(svc_num, obj->ssp.as_ipn.svc_num, "svc form");

    BSL_HostEID_Deinit(&eid);
}

TEST_CASE("")
TEST_CASE("any")
TEST_CASE("other:hi")
TEST_CASE("dtn://hi")
TEST_CASE("ipn:")
TEST_CASE("ipn:a.b")
TEST_CASE("ipn:0.0 ")           // space after
TEST_CASE("ipn:4294967296.0.0") // component too large
TEST_CASE("ipn:0.4294967296.0") // component too large
void test_BSL_HostEID_DecodeFromText_invalid(const char *text)
{
    BSL_HostEID_t eid;
    BSL_HostEID_Init(&eid);
    TEST_ASSERT_NOT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&eid, text));
    BSL_HostEID_Deinit(&eid);
}

TEST_CASE("ipn:0.0")
TEST_CASE("ipn:50.10")
TEST_CASE("ipn:0.0.0")
TEST_CASE("ipn:1.2.3")
TEST_CASE("ipn:4294967296.0") // authority present
void test_BSL_HostEID_DecodeFromText_loopback(const char *text)
{
    BSL_HostEID_t eid;
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_Init(&eid));

    TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&eid, text));
    TEST_ASSERT_NOT_NULL(eid.handle);

    string_t out;
    string_init(out);
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_EncodeToText(out, &eid));
    TEST_ASSERT_EQUAL_STRING(text, string_get_cstr(out));

    string_clear(out);
    BSL_HostEID_Deinit(&eid);
}
