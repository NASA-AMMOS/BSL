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
 * The sample policy provider itself uses Rust-native storage. This shim only
 * exposes tiny C helpers for operations that are still macro/static-inline-only
 * in the C side, plus BSL memory allocation callbacks.
 */
#ifndef BSL_SAMPLE_PP_FFI_H_
#define BSL_SAMPLE_PP_FFI_H_

#include "bsl/BPSecLib_Private.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void *BSLP_Rust_calloc(size_t nmemb, size_t size);
void BSLP_Rust_free(void *ptr);
void BSLP_Rust_Data_InitViewConst(BSL_Data_t *data, const uint8_t *ptr, size_t len);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_SAMPLE_PP_FFI_H_ */
