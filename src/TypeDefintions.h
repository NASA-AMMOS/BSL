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
 * General purpose BSL data-type definitions and commonly-used macros
 * @ingroup frontend
 */

#ifndef BSL_TYPE_DEFINTIONS_H
#define BSL_TYPE_DEFINTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Represents a value that when negative indicates a fault code, but
 * non-negative has context-dependent, but non-faulted, meaning.
 */
typedef int errcode_t;
#define assertNonNull(ptr) assert((ptr) != NULL)

/** Mark an unused parameter Within a function definition.
 * This avoids compiler warnings when parameters need to be present to satisfy
 * an interface but are otherwise unused.
 *
 * For example, this second parameter is marked unused:
 * @code{.c}
 * void myfunc(int param, int unused _U_)
 * @endcode
 */
#if defined(__GNUC__) || defined(__clang__)
#define _U_ __attribute__((unused)) // NOLINT
#elif defined(_MSC_VER)
#define _U_ __pragma(warning(suppress : 4100 4189))
#else
#define _U_
#endif

/** @def UNLIKELY(expr)
 * Hint to the compiler that the expression is expected to evaluate to false
 * and the associated branch is unlikely.
 * @param expr The expression to evaluate.
 * @return The boolean evaluation of the expression.
 */
/** @def LIKELY(expr)
 * Hint to the compiler that the expression is expected to evaluate to true
 * and the associated branch is likely.
 * @param expr The expression to evaluate.
 * @return The boolean evaluation of the expression.
 */
#ifndef UNLIKELY
#if defined(__GNUC__)
#define UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#define LIKELY(expr)   __builtin_expect(!!(expr), 1)
#else
#define UNLIKELY(expr) (expr)
#define LIKELY(expr)   (expr)
#endif
#endif /* UNLIKELY */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

bool BSL_AssertZeroed(const void *construct, size_t bytesize);


/*
// #define BSL_StaticArrayDef(element_type, element_capacity) 
//     typedef struct {
//         size_t _size;       
//         size_t _capacity;   
//         element_type elements[(element_capacity)];       
//     } Array_##element_type##_##element_capcity

// #define BSL_StaticArray_IsConsistent(arr) \
//     ( ((arr)->capacity == (sizeof((arr)->elements) / sizeof((arr)->elements[0]))) && \
//       ((arr)->size <= (arr)->capacity) )

// #define BSL_StaticArray_GetSize(arr) \
//     ((arr)->_size)

// #define BSL_StaticArray_AppendCopy(arr, elt) \
//     do { \
//         assert(BSL_StaticArray_IsConsistent((arr))); \
//         assert((arr)->_size < (arr)->_capacity); \
//         (arr)->elements[(arr)->_size++] = *(elt); \
//     } while(0)

// #define BSL_StaticArray_Init(arr) \
//     do { \
//         (arr)->size = 0; \
//         (arr).capacity = sizeof((arr).elements) / sizeof((arr).elements[0]); \
//         memset((arr), 0, sizeof(*arr)); \
//     } while (0)
*/


/** Check a condition and if not met return a specific value.
 *
 * @param cond The conditition to check.
 * @param val The return value if the check fails.
 */
#define CHKRET(cond, val) \
    if (!LIKELY(cond))    \
    {                     \
        return val;       \
    }
/// Return from void functions if condition fails.
#define CHKVOID(cond) CHKRET(cond, )
/// Return a null pointer if condition fails.
#define CHKNULL(cond) CHKRET(cond, NULL)
/// Return false if condition fails.
#define CHKFALSE(cond) CHKRET(cond, false)
/// Return the error value 1 if condition fails.
#define CHKERR1(cond) CHKRET(cond, 1)
/** Check a value for non-zero and return that value.
 * @warning The parameter is evaluated twice so should be a simple variable.
 *
 * @param value The value to check and conditionally return.
 */
#define CHKERRVAL(value) CHKRET(!(value), (value))

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_TYPE_DEFINTIONS_H */
