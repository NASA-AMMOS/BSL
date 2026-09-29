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
 * Linkable C helpers used by the Rust implementation of sample_pp.
 *
 * Many BSL and m*lib helpers used by the sample policy provider are static
 * inline functions or macro-generated container functions. Rust/bindgen can
 * see the data layout, but it cannot link against non-exported inline helper
 * bodies. This file exposes the small set of operations the Rust provider
 * needs while keeping policy logic in Rust.
 */
#ifndef BSL_SAMPLE_PP_FFI_H_
#define BSL_SAMPLE_PP_FFI_H_

#include "SamplePolicyProvider.h"

#include "bsl/cose_sc/CoseContext.h"
#include "bsl/dynamic/SecurityAction.h"
#include "bsl/dynamic/SecOperation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque, initialized temporary option map used while parsing policy JSON. */
typedef struct BSLP_RustVariantMap_s BSLP_RustVariantMap_t;

void *BSLP_Rust_calloc(size_t nmemb, size_t size);
void BSLP_Rust_free(void *ptr);

BSLP_RustVariantMap_t *BSLP_Rust_VariantMap_New(void);
void BSLP_Rust_VariantMap_Destroy(BSLP_RustVariantMap_t *self);
BSL_Variant_t *BSLP_Rust_VariantMap_Add(BSLP_RustVariantMap_t *self, int64_t key);
void BSLP_Rust_VariantMap_Erase(BSLP_RustVariantMap_t *self, int64_t key);

void BSLP_Rust_PolicyRule_DescriptionInit(BSLP_PolicyRule_t *self);
void BSLP_Rust_PolicyRule_DescriptionClear(BSLP_PolicyRule_t *self);
void BSLP_Rust_PolicyRule_DescriptionSetCstr(BSLP_PolicyRule_t *self, const char *description);
const char *BSLP_Rust_PolicyRule_DescriptionGetCstr(const BSLP_PolicyRule_t *self);
void BSLP_Rust_PolicyRule_OptionsInit(BSLP_PolicyRule_t *self);
void BSLP_Rust_PolicyRule_OptionsClear(BSLP_PolicyRule_t *self);
int BSLP_Rust_PolicyRule_MoveOptionsFromRustMap(BSLP_PolicyRule_t *self, BSLP_RustVariantMap_t *options);
BSL_Variant_t *BSLP_Rust_PolicyRule_AddOption(BSLP_PolicyRule_t *self, int64_t key);
bool BSLP_Rust_PolicyRule_IsConsistent(const BSLP_PolicyRule_t *self);
void BSLP_Rust_PolicyRule_CopyOptionsToSecOper(const BSLP_PolicyRule_t *self, BSL_SecOper_t *sec_oper);

bool BSLP_Rust_PolicyPredicate_IsConsistent(const BSLP_PolicyPredicate_t *self);

void BSLP_Rust_Data_InitViewConst(BSL_Data_t *data, const uint8_t *ptr, size_t len);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_SAMPLE_PP_FFI_H_ */
