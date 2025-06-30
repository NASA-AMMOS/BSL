/**
 * @file
 * @brief Moved pp* structs and functions here, as they have been copied-and-renamed elsewhere.
 * Kept for backwards compatibility of tests and mock_bpa process 
 * @ingroup backend_dyn
 */


#include <AdapterTypes.h>
#include <DeprecatedTypes.h>
#include <Logging.h>
#include <PolicyProvider.h>

#include "DeprecatedLibContext.h"


int BSL_PolicyRegistry_Inspect(BSL_LibCtx_t *lib, BSL_PolicyLocation_e location, const BSL_BundleCtx_t *bundle,
                               BSL_PolicyActionDeprecatedIList_t acts)
{
    BSL_PolicyDescList_it_t pp_it;
    for (BSL_PolicyDescList_it(pp_it, lib->pp_reg); !BSL_PolicyDescList_end_p(pp_it); BSL_PolicyDescList_next(pp_it))
    {
        BSL_PolicyDesc_t *desc = BSL_PolicyDescList_ref(pp_it);

        // use a separate list and splice it in if successful
        BSL_PolicyActionDeprecatedIList_t pp_acts;
        BSL_PolicyActionDeprecatedIList_init(pp_acts);
        int status = (desc->inspect)(lib, location, bundle, pp_acts, desc->user_data);
        if (status)
        {
            BSL_LOG_ERR("Failed to inspect from one Policy Provider, status %d", status);
            BSL_LibCtx_FreePolicyActionDeprecatedList(lib, pp_acts);
            BSL_PolicyActionDeprecatedIList_clear(pp_acts);
            continue;
        }

        // apply back reference
        BSL_PolicyActionDeprecatedIList_it_t act_it;
        for (BSL_PolicyActionDeprecatedIList_it(act_it, pp_acts); !BSL_PolicyActionDeprecatedIList_end_p(act_it);
             BSL_PolicyActionDeprecatedIList_next(act_it))
        {
            BSL_PolicyActionDeprecated_t *act = BSL_PolicyActionDeprecatedIList_ref(act_it);
            act->pp_ref             = desc;
        }

        BSL_PolicyActionDeprecatedIList_splice(acts, pp_acts);
        BSL_PolicyActionDeprecatedIList_clear(pp_acts);
    }

    return 0;
}

int BSL_PolicyRegistry_Finalize(BSL_LibCtx_t *lib, BSL_PolicyLocation_e location, const BSL_BundleCtx_t *bundle,
                                BSL_PolicyActionDeprecatedIList_t acts)
{
    BSL_PolicyDescList_it_t pp_it;
    for (BSL_PolicyDescList_it(pp_it, lib->pp_reg); !BSL_PolicyDescList_end_p(pp_it); BSL_PolicyDescList_next(pp_it))
    {
        BSL_PolicyDesc_t *desc = BSL_PolicyDescList_ref(pp_it);

        BSL_PolicyActionDeprecatedIList_t pp_acts;
        BSL_PolicyActionDeprecatedIList_init(pp_acts);

        // FIXME Inefficient grouping but it works for small counts
        BSL_PolicyActionDeprecatedIList_it_t act_it;
        for (BSL_PolicyActionDeprecatedIList_it(act_it, acts); !BSL_PolicyActionDeprecatedIList_end_p(act_it);)
        {
            BSL_PolicyActionDeprecated_t *act = BSL_PolicyActionDeprecatedIList_ref(act_it);
            // iterate first because items will be relocated
            BSL_PolicyActionDeprecatedIList_next(act_it);

            if (!(act->pp_ref))
            {
                BSL_LOG_WARNING("BSL_PolicyRegistry_Finalize has action without a pp_ref");
                continue;
            }
            if (act->pp_ref == desc)
            {
                BSL_PolicyActionDeprecatedIList_unlink(act);
                BSL_PolicyActionDeprecatedIList_push_back(pp_acts, act);
            }
        }
        if (BSL_PolicyActionDeprecatedIList_empty_p(pp_acts))
        {
            // nothing to do
            continue;
        }

        int status = (desc->finalize)(lib, location, bundle, pp_acts, desc->user_data);
        if (status)
        {
            BSL_LOG_ERR("Failed to finalize from one Policy Provider, status %d", status);
        }

        BSL_LibCtx_FreePolicyActionDeprecatedList(lib, pp_acts);
        BSL_PolicyActionDeprecatedIList_clear(pp_acts);
    }

    return 0;
}

bool BSL_SecCtx_ValidatePolicyActionDeprecated(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_PolicyActionDeprecated_t *act)
{
    CHKFALSE(lib);
    CHKFALSE(bundle);
    CHKFALSE(act);

    assert(0); // Not yet implemented.
//     // bsl_sec_op_list_it_t it;
//     // for (bsl_sec_op_list_it(it, act->ops); !bsl_sec_op_list_end_p(it); bsl_sec_op_list_next(it))
//     // {
//     //     const bsl_sec_op_t *sop = bsl_sec_op_list_cref(it);
//     //     // only one SC associated with this op
//     //     const BSL_SecCtxDesc_t *scd = BSL_SecCtxDict_cget(lib->sc_reg, sop->context_id);
//     //     if (!scd)
//     //     {
//     //         // Special case which should not happen
//     //         BSL_LOG_ERR("Failed to lookup Security Context ID %" PRId64, sop->context_id);
//     //         return false;
//     //     }

//     //     const bool isvalid = (scd->validate)(lib, bundle, sop);
//     //     if (!isvalid)
//     //     {
//     //         // fail fast on first invalid sop
//     //         return false;
//     //     }
//     // }

    // return true;
}


int BSL_LibCtx_AllocPolicyActionDeprecatedList(BSL_LibCtx_t *lib, BSL_PolicyActionDeprecatedIList_t list, size_t count)
{
    if (!lib)
    {
        return 1;
    }

    for (size_t ix = 0; ix < count; ++ix)
    {
        BSL_PolicyActionDeprecated_t *obj = BSL_PolicyActionPool_alloc(lib->action_pool);
        BSL_PolicyActionDeprecated_Init(obj);
        BSL_PolicyActionDeprecatedIList_push_back(list, obj);
    }

    return 0;
}

void BSL_LibCtx_FreePolicyActionDeprecatedList(BSL_LibCtx_t *lib, BSL_PolicyActionDeprecatedIList_t list)
{
    if (!lib)
    {
        return;
    }

    BSL_PolicyActionDeprecatedIList_it_t it;
    for (BSL_PolicyActionDeprecatedIList_it(it, list); !BSL_PolicyActionDeprecatedIList_end_p(it); BSL_PolicyActionDeprecatedIList_next(it))
    {
        BSL_PolicyActionDeprecated_t *obj = BSL_PolicyActionDeprecatedIList_ref(it);
        BSL_PolicyActionDeprecated_Deinit(obj);
        BSL_PolicyActionPool_free(lib->action_pool, obj);
    }
    BSL_PolicyActionDeprecatedIList_reset(list);
}

int BSL_PolicyActionDeprecated_Init(BSL_PolicyActionDeprecated_t *act)
{
    if (!act)
    {
        return 1;
    }
    memset(act, 0, sizeof(BSL_PolicyActionDeprecated_t));
    BSL_SecOperList_init(act->sec_oper_list);
    return 0;
}

int BSL_PolicyActionDeprecated_Deinit(BSL_PolicyActionDeprecated_t *act)
{
    assert(act != NULL);
    if (!act)
    {
        return 1;
    }

    while (BSL_SecOperList_size(act->sec_oper_list) > 0)
    {
        BSL_SecOper_t sec_oper;
        BSL_SecOperList_pop_back(&sec_oper, act->sec_oper_list);
        assert(sec_oper.sec_block_num > 0);
        assert(sec_oper.context_id > 0);
        BSL_SecOper_Deinit(&sec_oper);
    }
    assert(BSL_SecOperList_size(act->sec_oper_list) == 0);
    BSL_SecOperList_clear(act->sec_oper_list);
    return 0;
}
