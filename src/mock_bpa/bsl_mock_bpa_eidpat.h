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
 * Declarations for EID Pattern handling.
 * These are based on draft-sipos-dtn-eid-pattern @cite sipos-dtn-eid-pattern-02.
 */
#ifndef BSL_MOCK_BPA_EIDPAT_H_
#define BSL_MOCK_BPA_EIDPAT_H_

#include <inttypes.h>
#include <m-bptree.h>
#include <m-deque.h>

#include <BPSecLib_Private.h>

#include "bsl_mock_bpa_eid.h"

#ifdef __cplusplus
extern "C" {
#endif

/// A single numeric range segment pair
typedef struct
{
    /// The first value in this segment
    uint64_t first;
    /// The last value in this segment, also used to sort segments
    uint64_t last;
} bsl_eidpat_numrange_seg_t;

int  bsl_eidpat_numrange_seg_cmp(const bsl_eidpat_numrange_seg_t *left, const bsl_eidpat_numrange_seg_t *right);
bool bsl_eidpat_numrange_seg_overlap(const bsl_eidpat_numrange_seg_t *left, const bsl_eidpat_numrange_seg_t *right);

#define M_OPL_bsl_eidpat_numrange_seg_t() M_OPEXTEND(M_POD_OPLIST, CMP(API_6(bsl_eidpat_numrange_seg_cmp)))

/** @struct bsl_eidpat_numrage
 * An ordered set of range segments with fast lookup.
 */
/// @cond Doxygen_Suppress
BPTREE_DEF(bsl_eidpat_numrage, 4, bsl_eidpat_numrange_seg_t)
/// @endcond

/// The component type for a numeric tuple pattern
typedef enum
{
    /// A single numeric value
    BSL_EIDPAT_NUMCOMP_SINGLE,
    /// A multi-segment range of values
    BSL_EIDPAT_NUMCOMP_RANGE,
    /// This form has no associated value
    BSL_EIDPAT_NUMCOMP_WILDCARD,
} bsl_eidpat_numcomp_form_t;

/// Each component of a numeric tuple pattern
typedef struct
{
    /// The form of the component #val
    bsl_eidpat_numcomp_form_t form;
    /// The component value interpreted according to #form
    union
    {
        /// Used for ::BSL_EIDPAT_NUMCOMP_SINGLE
        uint64_t as_single;
        /// Used for ::BSL_EIDPAT_NUMCOMP_RANGE
        bsl_eidpat_numrage_t as_range;
    } val;
} bsl_eidpat_numcomp_t;

void bsl_eidpat_numcomp_init(bsl_eidpat_numcomp_t *obj);
void bsl_eidpat_numcomp_deinit(bsl_eidpat_numcomp_t *obj);
void bsl_eidpat_numcomp_set_form(bsl_eidpat_numcomp_t *obj, bsl_eidpat_numcomp_form_t form);
int  bsl_eidpat_numcomp_from_text(bsl_eidpat_numcomp_t *obj, const char *curs, const char **endptr);
bool bsl_eidpat_numcomp_match(const bsl_eidpat_numcomp_t *obj, uint64_t val);

/// Scheme-specific part for IPN scheme
typedef struct
{
    bsl_eidpat_numcomp_t auth;
    bsl_eidpat_numcomp_t node;
    bsl_eidpat_numcomp_t svc;
} bsl_eidpat_ipn_ssp_t;

void bsl_eidpat_ipn_ssp_init(bsl_eidpat_ipn_ssp_t *obj);
void bsl_eidpat_ipn_ssp_deinit(bsl_eidpat_ipn_ssp_t *obj);
bool bsl_eidpat_ipn_ssp_match(const bsl_eidpat_ipn_ssp_t *pat, const bsl_eid_ipn_ssp_t *val);

/// One item of an EID Pattern
typedef struct
{
    /// Code point for EID schemes from @cite iana:bundle
    uint64_t scheme;
    /// True if this is a match-any-SSP item
    bool any_ssp;

    /// Interpreted according to #scheme code when #any_ssp is @a false
    union
    {
        /// Used when #scheme is ::BSL_MOCK_EID_IPN
        bsl_eidpat_ipn_ssp_t as_ipn;
    } ssp;
} bsl_mock_eidpat_item_t;

int  bsl_mock_eidpat_item_init(bsl_mock_eidpat_item_t *obj);
void bsl_mock_eidpat_item_deinit(bsl_mock_eidpat_item_t *obj);
int  mock_bpa_eidpat_item_from_text(bsl_mock_eidpat_item_t *item, const char *text, const char **endptr);
bool mock_bpa_eidpat_item_match(const bsl_mock_eidpat_item_t *item, const bsl_mock_eid_t *eid);

#define M_OPL_bsl_mock_eidpat_item_t() \
    (INIT(API_2(bsl_mock_eidpat_item_init)), CLEAR(API_2(bsl_mock_eidpat_item_deinit)))

/// @cond Doxygen_Suppress
DEQUE_DEF(bsl_mock_eidpat_item_list, bsl_mock_eidpat_item_t)
/// @endcond

/// Struct to be used as a BSL_HostEIDPattern_t::handle
typedef struct
{
    /// The match-all state
    bool match_all;
    /** The list of pattern items.
     */
    bsl_mock_eidpat_item_list_t items;
} bsl_mock_eidpat_t;

/// Interface for BSL_HostDescriptors_t::eidpat_init
int mock_bpa_eidpat_init(BSL_HostEIDPattern_t *pat, void *user_data);

/// Interface for BSL_HostDescriptors_t::eidpat_deinit
void mock_bpa_eidpat_deinit(BSL_HostEIDPattern_t *pat, void *user_data);

/// Interface for BSL_HostDescriptors_t::eidpat_from_text
int mock_bpa_eidpat_from_text(BSL_HostEIDPattern_t *pat, const char *text, void *user_data);

/// Interface for BSL_HostDescriptors_t::eidpat_match
bool mock_bpa_eidpat_match(const BSL_HostEIDPattern_t *pat, const BSL_HostEID_t *eid, void *user_data);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_EIDPAT_H_
