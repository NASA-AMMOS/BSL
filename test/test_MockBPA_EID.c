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
#include <unity.h>

#include <BPSecLib_Private.h>

#include <bsl_mock_bpa.h>
#include <bsl_mock_bpa_eid.h>
#include <bsl_mock_bpa_eidpat.h>

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
void test_BSL_HostEID_DecodeFromText_valid(const char *text)
{
    BSL_HostEID_t eid;
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_Init(&eid));

    int res = BSL_HostEID_DecodeFromText(&eid, text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, res, "BSL_HostEID_DecodeFromText() failed");
    TEST_ASSERT_NOT_NULL(eid.handle);

    BSL_HostEID_Deinit(&eid);
}

TEST_CASE("", 0)
TEST_CASE("*:**", 0)
TEST_CASE("ipn:**", 1)
TEST_CASE("ipn:*.*.10", 1)
TEST_CASE("ipn:1.1.1|ipn:2.2.2", 2)
void test_BSL_HostEIDPattern_DecodeFromText_valid(const char *text, size_t count)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);

    int res = BSL_HostEIDPattern_DecodeFromText(&pat, text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, res, "BSL_HostEIDPattern_DecodeFromText() failed");
    const bsl_mock_eidpat_t *obj = pat.handle;
    TEST_ASSERT_NOT_NULL(obj);
    TEST_ASSERT_EQUAL_INT(count, bsl_mock_eidpat_item_list_size(obj->items));

    BSL_HostEIDPattern_Deinit(&pat);
}

TEST_CASE("ipn:0.0.0", BSL_EIDPAT_NUMCOMP_SINGLE, BSL_EIDPAT_NUMCOMP_SINGLE, BSL_EIDPAT_NUMCOMP_SINGLE)
TEST_CASE("ipn:*.*.*", BSL_EIDPAT_NUMCOMP_WILDCARD, BSL_EIDPAT_NUMCOMP_WILDCARD, BSL_EIDPAT_NUMCOMP_WILDCARD)
TEST_CASE("ipn:*.[1-3,5].10", BSL_EIDPAT_NUMCOMP_WILDCARD, BSL_EIDPAT_NUMCOMP_RANGE, BSL_EIDPAT_NUMCOMP_SINGLE)
TEST_CASE("ipn:*.[1-3,5,100-4294967296].10", BSL_EIDPAT_NUMCOMP_WILDCARD, BSL_EIDPAT_NUMCOMP_RANGE,
          BSL_EIDPAT_NUMCOMP_SINGLE)
void test_BSL_HostEIDPattern_DecodeFromText_ipn_valid(const char *text, bsl_eidpat_numcomp_form_t auth,
                                                      bsl_eidpat_numcomp_form_t node, bsl_eidpat_numcomp_form_t svc)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEIDPattern_DecodeFromText(&pat, text));
    const bsl_mock_eidpat_t *obj = pat.handle;
    TEST_ASSERT_NOT_NULL(obj);
    TEST_ASSERT_EQUAL_INT(1, bsl_mock_eidpat_item_list_size(obj->items));
    const bsl_mock_eidpat_item_t *item = bsl_mock_eidpat_item_list_front(obj->items);
    TEST_ASSERT_EQUAL_INT(BSL_MOCK_EID_IPN, item->scheme);
    TEST_ASSERT_EQUAL_INT(auth, item->ssp.as_ipn.auth.form);
    TEST_ASSERT_EQUAL_INT(node, item->ssp.as_ipn.node.form);
    TEST_ASSERT_EQUAL_INT(svc, item->ssp.as_ipn.svc.form);

    BSL_HostEIDPattern_Deinit(&pat);
}

TEST_CASE("any")
TEST_CASE("other:hi")
TEST_CASE("dtn://hi")
TEST_CASE("*")
TEST_CASE("**")
TEST_CASE("*:")
TEST_CASE("*:*")
TEST_CASE("ipn:")
TEST_CASE("ipn:a.b")
TEST_CASE("ipn:1")
TEST_CASE("ipn:1.")
TEST_CASE("ipn:1.a")
TEST_CASE("ipn:1.1.a")
TEST_CASE("ipn:1.1.1.")
TEST_CASE("ipn:1.1.1.a")
TEST_CASE("ipn:0.0 ")            // space after
TEST_CASE("ipn:0.0.0 ")          // space after
TEST_CASE("ipn:0.[a-9].0 ")      // invalid number
TEST_CASE("ipn:0.[0-b].0 ")      // invalid number
TEST_CASE("ipn:0.[1-5,3-7].0 ")  // overlapping range
TEST_CASE("ipn:0.[3-7,1-5].0 ")  // overlapping range
TEST_CASE("ipn:1.1.1,ipn:2.2.2") // comma instead of pipe
TEST_CASE("ipn:1.1.1|*:**")      // mix with match-all
TEST_CASE("*:**|ipn:1.1.1")      // mix with match-all
void test_BSL_HostEIDPattern_DecodeFromText_invalid(const char *text)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    TEST_ASSERT_NOT_EQUAL_INT(0, BSL_HostEIDPattern_DecodeFromText(&pat, text));
    BSL_HostEIDPattern_Deinit(&pat);
}

TEST_CASE("*:**", "ipn:0.0.0", true)
TEST_CASE("ipn:0.0.0", "ipn:0.0.0", true)
TEST_CASE("ipn:0.0.0", "ipn:0.0.1", false)
TEST_CASE("ipn:0.0.0", "ipn:0.1.0", false)
TEST_CASE("ipn:0.0.0", "ipn:1.0.0", false)
TEST_CASE("ipn:*.0.0", "ipn:1.0.0", true)
TEST_CASE("ipn:*.0.0", "ipn:4294967295.0.0", true)
TEST_CASE("ipn:*.[1-3,5].10", "ipn:10.0.10", false)
TEST_CASE("ipn:*.[1-3,5].10", "ipn:10.1.10", true)
TEST_CASE("ipn:*.[1-3,5].10", "ipn:10.3.10", true)
TEST_CASE("ipn:*.[1-3,5].10", "ipn:10.4.10", false)
TEST_CASE("ipn:*.[1-3,5].10", "ipn:10.5.10", true)
TEST_CASE("ipn:*.[1-3,5].10", "ipn:10.10.10", false)
void test_BSL_HostEIDPattern_IsMatch(const char *pat_text, const char *eid_text, bool expect)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEIDPattern_DecodeFromText(&pat, pat_text));

    BSL_HostEID_t eid;
    BSL_HostEID_Init(&eid);
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&eid, eid_text));

    TEST_ASSERT_EQUAL_INT(expect, BSL_HostEIDPattern_IsMatch(&pat, &eid));

    BSL_HostEID_Deinit(&eid);
    BSL_HostEIDPattern_Deinit(&pat);
}
