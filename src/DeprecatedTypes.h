#ifndef BSL_DEPRECATEDTYPES_H
#define BSL_DEPRECATEDTYPES_H

#include <m-i-list.h>

#include "BPSecTypes.h"
#include "BundleContext.h"
#include "LibContext.h"
#include "PolicyProvider.h"

/** A single action from a Policy Provider.
 * These are carried within a ::BSL_PolicyActionDeprecatedIList_t container.
 */
typedef struct BSL_PolicyActionDeprecated_s
{
    /** Reference to the Policy Provider which originated this action,
     * if the backend distinguishes these.
     * @note This is set by BSL itself and not by any policy provider.
     */
    void *pp_ref;

    /// @brief Replacement for old-style bsl_sec_op_list, used for temporary integration into old code.
    BSL_SecOperList_t sec_oper_list;

    /// Intrusive List interface
    M_ILIST_INTERFACE(BSL_PolicyActionDeprecatedIList, struct BSL_PolicyActionDeprecated_s);
} BSL_PolicyActionDeprecated_t;

/**
 * Initialize resources for policy provider action
 * @memberof BSL_PolicyAction_s
 *
 * @param[in,out] act pointer to policy provider action to initialize
 * @return 0 if successful
 */
int BSL_PolicyActionDeprecated_Init(BSL_PolicyActionDeprecated_t *act);

/**
 * Release resources from a policy provider action
 * @memberof BSL_PolicyAction_s
 *
 * @param[in,out] act pointer to policy provider action to deinitialize
 * @return 0 if successful
 */
int BSL_PolicyActionDeprecated_Deinit(BSL_PolicyActionDeprecated_t *act);

/** OPLIST for ::BSL_PolicyAction_s.
 * The instances are actually initialized by BSL_LibCtx_AllocPolicyActionDeprecatedList() and
 * de-initialized by BSL_LibCtx_FreePolicyActionDeprecatedList() outside of any specific container.
 */
#define M_OPL_BSL_PolicyActionDeprecated_t() ()

/**
 * @struct BSL_PolicyActionDeprecatedIList_t
 * This is a container for Policy Provider actions (::BSL_PolicyAction_s), which are the result of
 * processing individual bundles at a specific BPA location.
 * The action set is an instance of an [M-I-LIST](https://github.com/P-p-H-d/mlib/blob/master/README.md#m-i-list) from
 * @cite lib:mlib.
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
M_ILIST_DEF(BSL_PolicyActionDeprecatedIList, BSL_PolicyActionDeprecated_t)
/// @endcond
// NOLINTEND
/** Allocate a list of BSL_PolicyActionDeprecated_t from the memory pool.
 * Each of the structs is initialized to zeros.
 *
 * @param[in] lib The library context.
 * @param[in,out] list The list to append to.
 * The list must have already been initialized.
 * @param count Total number of actions desired.
 * @return Zero if successful.
 */
int BSL_LibCtx_AllocPolicyActionDeprecatedList(BSL_LibCtx_t *lib, BSL_PolicyActionDeprecatedIList_t list, size_t count);

/** Free a list of BSL_PolicyActionDeprecated_t back to the memory pool.
 *
 * @param[in] lib The library context.
 * @param[in,out] list The list containing actions to free.
 * The list itself will also be reset (but not cleared).
 */
void BSL_LibCtx_FreePolicyActionDeprecatedList(BSL_LibCtx_t *lib, BSL_PolicyActionDeprecatedIList_t list);

/** Signature for Policy Provider inspection of a bundle.
 *
 * @param[in] lib The library context.
 * @param location The location in BPA bundle flow where this is
 * taking place.
 * @param[in] bundle The bundle to inspect.
 * @param[out] acts The policy actions to perform.
 * @param[in] user_data Pointer to optional Policy Provider-specific data for the function.
 * @return Zero upon success or a non-zero error code.
 */
typedef int (*BSL_PolicyInspect_f)(BSL_LibCtx_t *lib, BSL_PolicyLocation_e location, const BSL_BundleCtx_t *bundle,
                                   BSL_PolicyActionDeprecatedIList_t acts, void *user_data);

/** Signature for Policy Provider finalizing of a bundle.
 *
 * @param[in] lib The library context.
 * @param location The location in BPA bundle flow where this is
 * taking place.
 * @param[in] bundle The bundle to inspect.
 * @param[in] acts The policy actions which were performed, with
 * @param[in] user_data Pointer to optional Policy Provider-specific data for the function.
 * @return Zero upon success or a non-zero error code.
 */
typedef int (*BSL_PolicyFinalize_f)(BSL_LibCtx_t *lib, BSL_PolicyLocation_e location, const BSL_BundleCtx_t *bundle,
                                    const BSL_PolicyActionDeprecatedIList_t acts, void *user_data);

/** Inspect a bundle by all policy providers and accumulate resulting actions.
 *
 * @param[in] lib The library context.
 * @param location The location in BPA bundle flow where this inspection is
 * taking place.
 * @param[in] bundle The bundle to inspect.
 * @param[out] acts The policy actions to perform.
 * @return Zero upon success or a non-zero error code.
 */
int BSL_PolicyRegistry_Inspect(BSL_LibCtx_t *lib, BSL_PolicyLocation_e location, const BSL_BundleCtx_t *bundle,
                               BSL_PolicyActionDeprecatedIList_t acts);

/** Finalize all actions on a bundle by checking with their original
 * policy provider.
 *
 * @param[in] lib The library context.
 * @param location The location in BPA bundle flow where this inspection is
 * taking place.
 * @param[in] bundle The bundle to inspect.
 * @param[in,out] acts The policy actions which were performed, with
 * The list will be cleared upon success.
 * @return Zero upon success or a non-zero error code.
 */
int BSL_PolicyRegistry_Finalize(BSL_LibCtx_t *lib, BSL_PolicyLocation_e location, const BSL_BundleCtx_t *bundle,
                                BSL_PolicyActionDeprecatedIList_t acts);

/** Validate all operations within a single action.
 *
 * @param[in] lib The library context.
 * @param[in] bundle The bundle being processed.
 * @param act The action to validate all operations of.
 * @return True if all operations are valid.
 * does not correlate to a registered security context.
 */
bool BSL_SecCtx_ValidatePolicyActionDeprecated(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_PolicyActionDeprecated_t *act);

/** Execute all operations within a single action.
 *
 * @param[in] lib The library context.
 * @param[in,out] bundle The bundle to modify.
 * @param[in,out] act The action to execute all operations of and mark
 * bsl_sec_op::exec_result on.
 * @return Pass-through the first failed operation, if any, or zero.
 */
int BSL_SecCtx_ExecutePolicyActionDeprecated(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, BSL_PolicyActionDeprecated_t *act);
#endif