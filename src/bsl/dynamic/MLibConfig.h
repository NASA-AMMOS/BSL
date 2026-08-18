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
 * @ingroup backend_dyn
 * M*LIB memory management configurations.
 */

#ifndef BSL_DYNAMIC_MLIBCONFIG_H_
#define BSL_DYNAMIC_MLIBCONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

/** Force the use of M_ prefixed macros for M*LIB
 */
#define M_USE_SMALL_NAME 0

#ifdef M_MEMORY_ALLOC
#undef M_MEMORY_ALLOC
#endif
/** Define to override value/struct allocation.
 * See m-core.h for details.
 */
#define M_MEMORY_ALLOC(ctx, type) ((type *)BSL_malloc(sizeof(type)))

#ifdef M_MEMORY_DEL
#undef M_MEMORY_DEL
#endif

/** Define to override value/struct deallocation.
 * See m-core.h for details.
 */
#define M_MEMORY_DEL(ctx, ptr) BSL_free(ptr)

#ifdef M_MEMORY_REALLOC
#undef M_MEMORY_REALLOC
#endif
/** Define to override array allocation.
 * See m-core.h for details.
 */
#define M_MEMORY_REALLOC(ctx, type, ptr, o, n) \
    (M_UNLIKELY((n) > SIZE_MAX / sizeof(type)) ? (type *)NULL : (type *)BSL_realloc((ptr), (n) * sizeof(type)))

#ifdef M_MEMORY_FREE
#undef M_MEMORY_FREE
#endif
/** Define to override array deallocation.
 * See m-core.h for details.
 */
#define M_MEMORY_FREE(ctx, type, ptr, o) BSL_free(ptr)

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_DYNAMIC_MLIBCONFIG_H_ */
