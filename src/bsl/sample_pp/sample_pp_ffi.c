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
 * @ingroup sample_pp
 * Linkable helpers for the Rust sample policy provider implementation.
 */

#include "sample_pp_ffi.h"

#include "bsl/front/BSLMemory.h"

#include <m-bptree.h>
#include <m-bstring.h>

#include <stddef.h>

struct BSLP_RustVariantMap_s
{
    BSLB_VariantPtrMap_t map;
};

void *BSLP_Rust_calloc(size_t nmemb, size_t size)
{
    return BSL_calloc(nmemb, size);
}

void BSLP_Rust_free(void *ptr)
{
    BSL_free(ptr);
}

BSLP_RustVariantMap_t *BSLP_Rust_VariantMap_New(void)
{
    BSLP_RustVariantMap_t *self = BSL_calloc(1, sizeof(*self));
    if (self)
    {
        BSLB_VariantPtrMap_init(self->map);
    }
    return self;
}

void BSLP_Rust_VariantMap_Destroy(BSLP_RustVariantMap_t *self)
{
    if (self)
    {
        BSLB_VariantPtrMap_clear(self->map);
        BSL_free(self);
    }
}

BSL_Variant_t *BSLP_Rust_VariantMap_Add(BSLP_RustVariantMap_t *self, int64_t key)
{
    if (!self)
    {
        return NULL;
    }
    return BSLB_VariantPtrMap_add(self->map, key);
}

void BSLP_Rust_VariantMap_Erase(BSLP_RustVariantMap_t *self, int64_t key)
{
    if (self)
    {
        BSLB_VariantPtrMap_erase(self->map, key);
    }
}

void BSLP_Rust_PolicyRule_DescriptionInit(BSLP_PolicyRule_t *self)
{
    if (self)
    {
        m_string_init(self->description);
    }
}

void BSLP_Rust_PolicyRule_DescriptionClear(BSLP_PolicyRule_t *self)
{
    if (self)
    {
        m_string_clear(self->description);
    }
}

void BSLP_Rust_PolicyRule_DescriptionSetCstr(BSLP_PolicyRule_t *self, const char *description)
{
    if (self && description)
    {
        m_string_set_cstr(self->description, description);
    }
}

const char *BSLP_Rust_PolicyRule_DescriptionGetCstr(const BSLP_PolicyRule_t *self)
{
    return self ? m_string_get_cstr(self->description) : NULL;
}

void BSLP_Rust_PolicyRule_OptionsInit(BSLP_PolicyRule_t *self)
{
    if (self)
    {
        BSLB_VariantPtrMap_init(self->options);
    }
}

void BSLP_Rust_PolicyRule_OptionsClear(BSLP_PolicyRule_t *self)
{
    if (self)
    {
        BSLB_VariantPtrMap_clear(self->options);
    }
}

BSL_Variant_t *BSLP_Rust_PolicyRule_AddOption(BSLP_PolicyRule_t *self, int64_t key)
{
    if (!self)
    {
        return NULL;
    }
    return BSLB_VariantPtrMap_add(self->options, key);
}

int BSLP_Rust_PolicyRule_MoveOptionsFromRustMap(BSLP_PolicyRule_t *self, BSLP_RustVariantMap_t *options)
{
    if (!self || !options)
    {
        return BSL_ERR_ARG_NULL;
    }

    BSLB_VariantPtrMap_it_t opt_it;
    for (BSLB_VariantPtrMap_it(opt_it, options->map); !BSLB_VariantPtrMap_end_p(opt_it);
         BSLB_VariantPtrMap_next(opt_it))
    {
        const BSLB_VariantPtrMap_subtype_ct *pair = BSLB_VariantPtrMap_cref(opt_it);
        const int64_t key                           = *pair->key_ptr;
        BSL_Variant_t *dest                         = BSLB_VariantPtrMap_add(self->options, key);
        BSL_Variant_Set(dest, BSLB_VariantPtr_cref(*pair->value_ptr));
    }

    /* Do not clear options->map here. The TempOptions owner in Rust still
     * owns and destroys the temporary map. Clearing it here makes the later
     * BSLP_Rust_VariantMap_Destroy() call clear an already-cleared m*lib map,
     * which trips VariantPtrMap's root assertion.
     */
    return BSL_SUCCESS;
}

bool BSLP_Rust_PolicyRule_IsConsistent(const BSLP_PolicyRule_t *self)
{
    return self && BSL_SECROLE_ISVALID(self->role) && BSL_SecBlockType_IsSecBlock(self->sec_block_type)
        && (self->context_id > 0) && (self->failure_action_code != BSL_POLICYACTION_UNDEFINED);
}

void BSLP_Rust_PolicyRule_CopyOptionsToSecOper(const BSLP_PolicyRule_t *self, BSL_SecOper_t *sec_oper)
{
    if (!self || !sec_oper)
    {
        return;
    }

    BSLB_VariantPtrMap_it_t opt_it;
    for (BSLB_VariantPtrMap_it(opt_it, self->options); !BSLB_VariantPtrMap_end_p(opt_it);
         BSLB_VariantPtrMap_next(opt_it))
    {
        const BSLB_VariantPtrMap_subtype_ct *pair = BSLB_VariantPtrMap_cref(opt_it);
        const int64_t opt_id                       = *pair->key_ptr;
        BSL_Variant_t *dest                        = BSL_SecOper_AddOption(sec_oper, opt_id);
        BSL_Variant_Set(dest, BSLB_VariantPtr_cref(*pair->value_ptr));
    }
}

bool BSLP_Rust_PolicyPredicate_IsConsistent(const BSLP_PolicyPredicate_t *self)
{
    return self && (self->location >= BSL_POLICYLOCATION_APPIN) && (self->location <= BSL_POLICYLOCATION_CLOUT)
        && self->src_eid_pattern.handle && self->secsrc_eid_pattern.handle && self->dst_eid_pattern.handle;
}

void BSLP_Rust_Data_InitViewConst(BSL_Data_t *data, const uint8_t *ptr, size_t len)
{
    if (data)
    {
        BSL_Data_InitView(data, len, (BSL_DataPtr_t)ptr);
    }
}
