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

/** @file
 * @ingroup mock_bpa
 * Definitions for EID handling.
 */
#include "bsl_mock_bpa_eid.h"
#include <BSLConfig.h>
#include <BPSecLib_Private.h>

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <sys/types.h>

int MockBPA_GetEid(const void *user_data, BSL_HostEID_t *result_eid)
{
    const char *local_ipn = getenv("BSL_TEST_LOCAL_IPN_EID");
    int         x         = mock_bpa_eid_from_text(result_eid, local_ipn, (void *)user_data);
    return (0 == x) ? 0 : -1;
}

void bsl_mock_eid_init(bsl_mock_eid_t *eid)
{
    CHKVOID(eid);
    memset(eid, 0, sizeof(bsl_mock_eid_t));
}

void bsl_mock_eid_deinit(bsl_mock_eid_t *eid)
{
    CHKVOID(eid);
    switch (eid->scheme)
    {
        case BSL_MOCK_EID_IPN:
            break;
        default:
            BSL_Data_Deinit(&(eid->ssp.as_raw));
            break;
    }
    memset(eid, 0, sizeof(bsl_mock_eid_t));
}

int MockBPA_EID_Init(void *user_data _U_, BSL_HostEID_t *eid)
{
    CHKERR1(eid);
    memset(eid, 0, sizeof(BSL_HostEID_t));
    eid->handle = BSL_MALLOC(sizeof(bsl_mock_eid_t));
    if (!(eid->handle))
    {
        return -2;
    }
    bsl_mock_eid_init(eid->handle);
    return 0;
}

void MockBPA_EID_Deinit(void *user_data _U_, BSL_HostEID_t *eid)
{
    CHKVOID(eid);
    if (eid->handle)
    {
        bsl_mock_eid_deinit(eid->handle);
        BSL_FREE(eid->handle);
    }
    memset(eid, 0, sizeof(BSL_HostEID_t));
}

int mock_bpa_get_secsrc(BSL_HostEID_t *eid, void *user_data)
{
    const char *local_ipn = getenv("BSL_TEST_LOCAL_IPN_EID");
    return mock_bpa_eid_from_text(eid, local_ipn, user_data);
}

int mock_bpa_eid_from_text(BSL_HostEID_t *eid, const char *text, void *user_data _U_)
{
    CHKERR1(eid);
    CHKERR1(text);

    // clean up if necessary
    // bsl_mock_eid_deinit(eid->handle);

    const char *curs = text;
    const char *end  = curs + strlen(text);
    char       *pend = strchr(text, ':');
    if (pend == NULL)
    {
        return 2;
    }
    size_t scheme_len = pend - text;

    if (strncasecmp(text, "ipn", scheme_len) == 0)
    {
        curs = pend + 1;

        uint64_t p1, p2, p3;
        int      len1, len2;
        // use scanf to handle two or three component case
        int res = sscanf(curs, "%" PRIu64 ".%" PRIu64 "%n.%" PRIu64 "%n", &p1, &p2, &len1, &p3, &len2);

        bsl_eid_ipn_ssp_t ipn_ssp;
        if (res == 2)
        {
            // two components
            ipn_ssp.ncomp    = 2;
            ipn_ssp.auth_num = p1 >> 32;
            ipn_ssp.node_num = p1 & 0xFFFFFFFF;
            ipn_ssp.svc_num  = p2;
            curs += len1;
        }
        else if (res == 3)
        {
            // three components
            ipn_ssp.ncomp    = 3;
            ipn_ssp.auth_num = p1;
            ipn_ssp.node_num = p2;
            ipn_ssp.svc_num  = p3;
            curs += len2;

            if ((ipn_ssp.auth_num > UINT32_MAX) || (ipn_ssp.node_num > UINT32_MAX))
            {
                // parts larger than allowed
                return 4;
            }
        }
        else
        {
            return 4;
        }

        if (curs < end)
        {
            // extra text
            return 5;
        }

        bsl_mock_eid_t *obj = (bsl_mock_eid_t *)eid->handle;
        assert(eid->handle != NULL);
        obj->scheme     = BSL_MOCK_EID_IPN;
        obj->ssp.as_ipn = ipn_ssp;
    }
    else
    {
        // unhandled scheme
        return 3;
    }

    return 0;
}

// int mock_bpa_eid_to_text(string_t out, const BSL_HostEID_t *eid, void *user_data _U_)
// {
//     CHKERR1(eid);
//     CHKERR1(eid->handle);
//     bsl_mock_eid_t *obj = (bsl_mock_eid_t *)eid->handle;

//     switch (obj->scheme)
//     {
//         case BSL_MOCK_EID_IPN:
//         {
//             const bsl_eid_ipn_ssp_t *ipn = &(obj->ssp.as_ipn);
//             switch (ipn->ncomp)
//             {
//                 case 2:
//                     string_printf(out, "ipn:%" PRIu64 ".%" PRIu64, (ipn->auth_num << 32) | ipn->node_num,
//                     ipn->svc_num); break;
//                 case 3:
//                     string_printf(out, "ipn:%" PRIu64 ".%" PRIu64 ".%" PRIu64, ipn->auth_num, ipn->node_num,
//                                   ipn->svc_num);
//                     break;
//                 default:
//                     // not valid
//                     break;
//             }
//             break;
//         }
//         default:
//             string_printf(out, "<unknown EID scheme: %d>", obj->scheme);
//             break;
//     }
//     return 0;
// }
