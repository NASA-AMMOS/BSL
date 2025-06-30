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
/** @file
 * Abstract interface for a BSL library context.
 * @ingroup frontend
 */
#ifndef BSL_CTX_H_
#define BSL_CTX_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Forward declaration for this type
typedef struct BSL_LibCtx_s BSL_LibCtx_t;

/** Initialize resources for a library context.
 *
 * @param[in,out] lib The library context.
 * @return Zero if successful.
 */
int BSL_LibCtx_Init(BSL_LibCtx_t *lib);

/** Initialize a library context as a copy from an existing context.
 *
 * @param[in,out] lib The library context.
 * @param src The existing context to copy from.
 * @return Zero if successful.
 */
int BSL_LibCtx_Init2(BSL_LibCtx_t *lib, const BSL_LibCtx_t *src);

/** Release resources from a library context.
 *
 * @param lib The library context.
 * @return Zero if successful.
 */
int BSL_LibCtx_Deinit(BSL_LibCtx_t *lib);


#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_CTX_H_
