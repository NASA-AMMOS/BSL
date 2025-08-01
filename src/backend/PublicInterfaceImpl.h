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
 * Private interface for the dynamic backend library context.
 * @ingroup backend_dyn
 */
#ifndef BSL_CTX_DYN_H_
#define BSL_CTX_DYN_H_

#include <m-dict.h>

#include <BPSecLib_Private.h>
#include <BPSecLib_Public.h>

#ifdef __cplusplus
extern "C" {
#endif

// NOLINTBEGIN
/// @cond Doxygen_Suppress
/// Stable dict of security context descriptors (key: context id | value: descriptor struct)
DICT_DEF2(BSL_SecCtxDict, uint64_t, M_BASIC_OPLIST, BSL_SecCtxDesc_t, M_POD_OPLIST)
/// @endcond
// NOLINTEND

/** Concrete definition of library context.
 */
struct BSL_LibCtx_s
{
    BSL_PolicyDesc_t policy_registry;
    BSL_SecCtxDict_t sc_reg;
};

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_CTX_DYN_H_
