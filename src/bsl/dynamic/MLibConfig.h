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
