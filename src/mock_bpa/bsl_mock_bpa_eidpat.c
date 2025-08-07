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
#include "bsl_mock_bpa_eidpat.h"
#include <BPSecLib_Private.h>
#include <strings.h>

int bsl_eidpat_numrange_seg_cmp(const bsl_eidpat_numrange_seg_t *left, const bsl_eidpat_numrange_seg_t *right)
{
    if (!left || !right)
    {
        // not valid
        return 0;
    }
    if (left->last < right->last)
    {
        return -1;
    }
    if (left->last > right->last)
    {
        return 1;
    }
    return 0;
}

bool bsl_eidpat_numrange_seg_overlap(const bsl_eidpat_numrange_seg_t *left, const bsl_eidpat_numrange_seg_t *right)
{
    if (!left || !right)
    {
        // not valid
        return false;
    }

    uint64_t max_first = (left->first > right->first) ? left->first : right->first;
    uint64_t min_last  = (left->last < right->last) ? left->last : right->last;
    return (max_first <= min_last);
}

void bsl_eidpat_numcomp_init(bsl_eidpat_numcomp_t *obj)
{
    obj->form = BSL_EIDPAT_NUMCOMP_WILDCARD;
}

void bsl_eidpat_numcomp_deinit(bsl_eidpat_numcomp_t *obj)
{
    if (obj->form == BSL_EIDPAT_NUMCOMP_RANGE)
    {
        bsl_eidpat_numrage_clear(obj->val.as_range);
    }
    obj->form = BSL_EIDPAT_NUMCOMP_WILDCARD;
}

void bsl_eidpat_numcomp_set_form(bsl_eidpat_numcomp_t *obj, bsl_eidpat_numcomp_form_t form)
{
    if (obj->form == form)
    {
        return;
    }

    if (obj->form == BSL_EIDPAT_NUMCOMP_RANGE)
    {
        bsl_eidpat_numrage_clear(obj->val.as_range);
    }

    obj->form = form;
    if (form == BSL_EIDPAT_NUMCOMP_RANGE)
    {
        bsl_eidpat_numrage_init(obj->val.as_range);
    }
}

static int one_uint64_from_text(uint64_t *val, const char *curs, const char **endptr)
{
    char *pend;
    *val = strtoul(curs, &pend, 10);
    if (pend == curs)
    {
        // failed decoding
        return 2;
    }
    *endptr = pend;
    return 0;
}

int bsl_eidpat_numcomp_from_text(bsl_eidpat_numcomp_t *obj, const char *curs, const char **endptr)
{
    if (*curs == '\0')
    {
        // no text at start
        return 4;
    }

    if (*curs == '*')
    {
        // wildcard
        bsl_eidpat_numcomp_set_form(obj, BSL_EIDPAT_NUMCOMP_WILDCARD);
        ++curs;
    }
    else if (*curs == '[')
    {
        // range
        bsl_eidpat_numcomp_set_form(obj, BSL_EIDPAT_NUMCOMP_RANGE);
        ++curs;

        const char *range_end = strchr(curs, ']');
        while (curs < range_end)
        {
            bsl_eidpat_numrange_seg_t seg;

            const char *pend;
            if (one_uint64_from_text(&seg.first, curs, &pend))
            {
                return 4;
            }
            curs = pend;

            // determine interval or single value
            if (*curs == '-')
            {
                ++curs;

                if (one_uint64_from_text(&seg.last, curs, &pend))
                {
                    return 4;
                }
                curs = pend;
            }
            else
            {
                // single-value segment
                seg.last = seg.first;
            }

            // check for overlaps
            const bsl_eidpat_numrange_seg_t *near_low = NULL, *near_high = NULL;
            if (!bsl_eidpat_numrage_empty_p(obj->val.as_range))
            {
                bsl_eidpat_numrage_it_t existing;
                bsl_eidpat_numrage_it_from(existing, obj->val.as_range, seg);
                if (bsl_eidpat_numrage_end_p(existing))
                {
                    near_low = bsl_eidpat_numrage_max(obj->val.as_range);
                }
                else
                {
                    near_high = bsl_eidpat_numrage_cref(existing);
                    // FIXME no bsl_eidpat_numrage_prev() function to go backward
                }
            }

            if (near_low && bsl_eidpat_numrange_seg_overlap(&seg, near_low))
            {
                // overlap with existing
                return 6;
            }
            if (near_high && bsl_eidpat_numrange_seg_overlap(&seg, near_high))
            {
                // overlap with existing
                return 6;
            }
            bsl_eidpat_numrage_push(obj->val.as_range, seg);

            // last item has no trailing comma
            if (*curs == ',')
            {
                ++curs;
            }
        }
        ++curs;
    }
    else
    {
        // single value
        bsl_eidpat_numcomp_set_form(obj, BSL_EIDPAT_NUMCOMP_SINGLE);
        const char *pend;
        if (one_uint64_from_text(&obj->val.as_single, curs, &pend))
        {
            return 4;
        }
        curs = pend;
    }

    *endptr = curs;
    return 0;
}

bool bsl_eidpat_numcomp_match(const bsl_eidpat_numcomp_t *obj, uint64_t val)
{
    switch (obj->form)
    {
        case BSL_EIDPAT_NUMCOMP_WILDCARD:
            // value-independent
            return true;
        case BSL_EIDPAT_NUMCOMP_SINGLE:
            return obj->val.as_single == val;
        case BSL_EIDPAT_NUMCOMP_RANGE:
        {
            // search for singleton segment
            bsl_eidpat_numrange_seg_t key = {
                .first = val,
                .last  = val,
            };
            bsl_eidpat_numrage_it_t it;
            bsl_eidpat_numrage_it_from(it, obj->val.as_range, key);
            if (bsl_eidpat_numrage_end_p(it))
            {
                return false;
            }
            const bsl_eidpat_numrange_seg_t *found = bsl_eidpat_numrage_cref(it);
            return ((val >= found->first) && (val <= found->last));
        }
    }
    return false; // LCOV_EXCL_LINE
}

void bsl_eidpat_ipn_ssp_init(bsl_eidpat_ipn_ssp_t *obj)
{
    bsl_eidpat_numcomp_init(&(obj->auth));
    bsl_eidpat_numcomp_init(&(obj->node));
    bsl_eidpat_numcomp_init(&(obj->svc));
}

void bsl_eidpat_ipn_ssp_deinit(bsl_eidpat_ipn_ssp_t *obj)
{
    bsl_eidpat_numcomp_deinit(&(obj->auth));
    bsl_eidpat_numcomp_deinit(&(obj->node));
    bsl_eidpat_numcomp_deinit(&(obj->svc));
}

bool bsl_eidpat_ipn_ssp_match(const bsl_eidpat_ipn_ssp_t *pat, const bsl_eid_ipn_ssp_t *val)
{
    return (bsl_eidpat_numcomp_match(&(pat->auth), val->auth_num)
            && bsl_eidpat_numcomp_match(&(pat->node), val->node_num)
            && bsl_eidpat_numcomp_match(&(pat->svc), val->svc_num));
}

int bsl_mock_eidpat_item_init(bsl_mock_eidpat_item_t *obj)
{
    memset(obj, 0, sizeof(bsl_mock_eidpat_item_t));
    return 0;
}

void bsl_mock_eidpat_item_deinit(bsl_mock_eidpat_item_t *obj)
{
    switch (obj->scheme)
    {
        case BSL_MOCK_EID_IPN:
            bsl_eidpat_ipn_ssp_deinit(&(obj->ssp.as_ipn));
            break;
        default:
            break;
    }
    memset(obj, 0, sizeof(bsl_mock_eidpat_item_t));
}

int mock_bpa_eidpat_item_from_text(bsl_mock_eidpat_item_t *item, const char *text, const char **endptr)
{
    CHKERR1(item);
    CHKERR1(text);
    CHKERR1(endptr);

    // clean up if necessary
    bsl_mock_eidpat_item_deinit(item);

    const char *curs = text;
    const char *pend = strchr(text, ':');
    if (pend == NULL)
    {
        return 2;
    }
    size_t scheme_len = pend - text;
    curs              = pend + 1;

    if (strncasecmp(text, "ipn", scheme_len) == 0)
    {
        item->scheme = BSL_MOCK_EID_IPN;

        if (strncmp(curs, "**", 2) == 0)
        {
            item->any_ssp = true;
            curs += 2;
        }
        else
        {
            bsl_eidpat_ipn_ssp_t *ipn_ssp = &(item->ssp.as_ipn);
            bsl_eidpat_ipn_ssp_init(ipn_ssp);

            if (bsl_eidpat_numcomp_from_text(&ipn_ssp->auth, curs, &pend))
            {
                bsl_eidpat_ipn_ssp_deinit(ipn_ssp);
                return 4;
            }
            curs = pend;
            if (*curs != '.')
            {
                bsl_eidpat_ipn_ssp_deinit(ipn_ssp);
                return 4;
            }
            ++curs;

            if (bsl_eidpat_numcomp_from_text(&ipn_ssp->node, curs, &pend))
            {
                bsl_eidpat_ipn_ssp_deinit(ipn_ssp);
                return 4;
            }
            curs = pend;
            if (*curs != '.')
            {
                bsl_eidpat_ipn_ssp_deinit(ipn_ssp);
                return 4;
            }
            ++curs;

            if (bsl_eidpat_numcomp_from_text(&ipn_ssp->svc, curs, &pend))
            {
                bsl_eidpat_ipn_ssp_deinit(ipn_ssp);
                return 4;
            }
            curs = pend;
        }
    }
    else
    {
        // unhandled scheme
        return 3;
    }

    *endptr = curs;
    return 0;
}

bool mock_bpa_eidpat_item_match(const bsl_mock_eidpat_item_t *item, const bsl_mock_eid_t *eid)
{
    CHKERR1(item);
    CHKERR1(eid);

    if (item->scheme != eid->scheme)
    {
        // no possibility
        return false;
    }

    switch (item->scheme)
    {
        case BSL_MOCK_EID_IPN:
            return bsl_eidpat_ipn_ssp_match(&(item->ssp.as_ipn), &(eid->ssp.as_ipn));
        default:
            BSL_LOG_ERR("EID Pattern scheme %" PRIu64 " not handled", item->scheme);
            break;
    }
    return false;
}

int mock_bpa_eidpat_init(BSL_HostEIDPattern_t *pat, void *user_data _U_)
{
    CHKERR1(pat);
    memset(pat, 0, sizeof(BSL_HostEIDPattern_t));
    pat->handle = BSL_MALLOC(sizeof(bsl_mock_eidpat_t));
    if (!(pat->handle))
    {
        return 2;
    }
    {
        memset(pat->handle, 0, sizeof(bsl_mock_eidpat_t));
        bsl_mock_eidpat_t *obj = pat->handle;
        bsl_mock_eidpat_item_list_init(obj->items);
    }
    return 0;
}

static void bsl_mock_eidpat_deinit(bsl_mock_eidpat_t *pat)
{
    CHKVOID(pat);
    bsl_mock_eidpat_item_list_clear(pat->items);
    memset(pat, 0, sizeof(bsl_mock_eidpat_t));
}

void mock_bpa_eidpat_deinit(BSL_HostEIDPattern_t *pat, void *user_data _U_)
{
    CHKVOID(pat);
    if (pat->handle)
    {
        bsl_mock_eidpat_deinit(pat->handle);
        BSL_FREE(pat->handle);
    }
    memset(pat, 0, sizeof(BSL_HostEIDPattern_t));
}

int mock_bpa_eidpat_from_text(BSL_HostEIDPattern_t *pat, const char *text, void *user_data _U_)
{
    CHKERR1(pat);
    CHKERR1(text);
    bsl_mock_eidpat_t *obj = pat->handle;
    CHKERR1(obj);

    // clean up if necessary
    obj->match_all = false;
    bsl_mock_eidpat_item_list_reset(obj->items);

    const char *curs = text;
    const char *end  = curs + strlen(text);
    const char *pend;

    while (curs < end)
    {
        if (strncmp(curs, "*:**", 4) == 0)
        {
            // leave items empty and finish
            obj->match_all = true;
            curs += 4;
        }
        else
        {
            bsl_mock_eidpat_item_t *item = bsl_mock_eidpat_item_list_push_back_new(obj->items);
            if (mock_bpa_eidpat_item_from_text(item, curs, &pend))
            {
                bsl_mock_eidpat_item_list_reset(obj->items);
                return 3;
            }
            curs = pend;
        }

        if (*curs == '|')
        {
            ++curs;
        }
    }

    // match-all cannot be combined with others
    if (obj->match_all && !bsl_mock_eidpat_item_list_empty_p(obj->items))
    {
        return 6;
    }

    return 0;
}

bool mock_bpa_eidpat_match(const BSL_HostEIDPattern_t *pat, const BSL_HostEID_t *eid, void *user_data _U_)
{
    CHKERR1(pat);
    CHKERR1(pat->handle);
    CHKERR1(eid);
    CHKERR1(eid->handle);
    bsl_mock_eidpat_t *patobj = (bsl_mock_eidpat_t *)pat->handle;
    bsl_mock_eid_t    *eidobj = (bsl_mock_eid_t *)eid->handle;

    // any-scheme condition
    if (patobj->match_all)
    {
        return true;
    }

    bsl_mock_eidpat_item_list_it_t it;
    for (bsl_mock_eidpat_item_list_it(it, patobj->items); !bsl_mock_eidpat_item_list_end_p(it);
         bsl_mock_eidpat_item_list_next(it))
    {
        const bsl_mock_eidpat_item_t *item = bsl_mock_eidpat_item_list_cref(it);
        if (mock_bpa_eidpat_item_match(item, eidobj))
        {
            return true;
        }
    }
    return false;
}
