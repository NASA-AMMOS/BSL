/** @file
 * @brief Implementation of functions to interact with the security context
 * @ingroup backend_dyn
 */

#include <AdapterTypes.h>
#include <BundleContext.h>
#include <Logging.h>
#include <SecurityContext.h>

#include "DynBundleContext.h"

// Only for the security context execute.
#include "DeprecatedLibContext.h"

void BSL_SecOutcome_Init(BSL_SecOutcome_t *self, const BSL_SecOper_t *sec_oper, size_t allocation_size)
{
    assert(self != NULL);
    assert(sec_oper != NULL);
    assert(allocation_size > 0);

    memset(self, 0, sizeof(*self));
    self->is_success = 0;
    BSL_SecParamList_init(self->param_list);
    BSL_SecResultList_init(self->result_list);
    self->sec_oper = sec_oper;
    BSL_Data_InitBuffer(&self->allocation, allocation_size);
    assert(BSL_SecOutcome_IsConsistent(self));
}

void BSL_SecOutcome_Deinit(BSL_SecOutcome_t *self)
{
    assert(BSL_SecOutcome_IsConsistent(self));
    BSL_SecParamList_clear(self->param_list);
    BSL_SecResultList_clear(self->result_list);
    BSL_Data_Deinit(&self->allocation);
    memset(self, 0, sizeof(*self));
}

bool BSL_SecOutcome_IsConsistent(const BSL_SecOutcome_t *self)
{
    assert(self != NULL);
    assert(self->sec_oper != NULL);
    assert(self->allocation.len > 0);
    assert(self->allocation.ptr != NULL);
    
    // Invariant: If it is not successful, it should not return any results
    const size_t result_len = BSL_SecResultList_size(self->result_list);
    if (self->is_success)
    {
        assert(result_len > 0);
    }
    else
    {
        // assert(result_len == 0);
    }

    // Invariant: Parameter list contains something (i.e., calling it doesn't cause problems)
    // NOLINTNEXTLINE
    assert(BSL_SecParamList_size(self->param_list) < 1000);
    return true;
}

void BSL_SecOutcome_AppendResult(BSL_SecOutcome_t *self, const BSL_SecResult_t *sec_result)
{
    assert(BSL_SecResult_IsConsistent(sec_result));
    assert(BSL_SecOutcome_IsConsistent(self));

    size_t size0 = BSL_SecResultList_size(self->result_list);
    BSL_SecResultList_push_back(self->result_list, *sec_result);

    assert(size0 + 1 == BSL_SecResultList_size(self->result_list));
    assert(BSL_SecOutcome_IsConsistent(self));
}

size_t BSL_SecOutcome_GetResultCount(const BSL_SecOutcome_t *self)
{
    assert(BSL_SecOutcome_IsConsistent(self));
    return BSL_SecResultList_size(self->result_list);
}

const BSL_SecResult_t *BSL_SecOutcome_GetResultAtIndex(const BSL_SecOutcome_t *self, size_t index)
{
    assert(BSL_SecOutcome_IsConsistent(self));
    assert(index < BSL_SecOutcome_GetResultCount(self));
    return BSL_SecResultList_cget(self->result_list, index);

}

void BSL_SecOutcome_AppendParam(BSL_SecOutcome_t *self, const BSL_SecParam_t *param)
{
    assert(BSL_SecParam_IsConsistent(param));
    assert(BSL_SecOutcome_IsConsistent(self));

    size_t size0 = BSL_SecParamList_size(self->param_list);
    BSL_SecParamList_push_back(self->param_list, *param);

    assert(size0 + 1 == BSL_SecParamList_size(self->param_list));
    assert(BSL_SecOutcome_IsConsistent(self));
}

int BSL_ExecBIBSource(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleCtx_t *bundle,
                      BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    (void)lib;
    assert(bundle != NULL);
    assert(sec_oper != NULL);
    assert(outcome != NULL);
    int blk_id;
    if ((blk_id = BSL_BundleCtx_CreateBlock((BSL_BundleCtx_t *)bundle, BSL_SECBLOCKTYPE_BIB)) < 0)
    {
        BSL_LOG_ERR("Could not prepare security context execution as security source");
        return -1;
    }
    sec_oper->sec_block_num = (uint64_t)blk_id;
    const int res           = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (res != 0 || outcome->is_success == false)
    {
        BSL_LOG_ERR("BIB Source failed!");
        return -1;
    }

    BSL_BundleBlock_t *sec_blk =
        (BSL_BundleBlock_t *)BSL_BundleCtx_GetBlockById((BSL_BundleCtx_t *)bundle, sec_oper->sec_block_num);
    assert(sec_blk->abs_sec_blk != NULL);
    sec_blk->abs_sec_blk->sec_context_id = sec_oper->context_id;
    BSL_AbsSecBlock_AddTarget(sec_blk->abs_sec_blk, sec_oper->target_block_num);

    size_t index;
    size_t n_results = BSL_SecResultList_size(outcome->result_list);
    for (index = 0; index < n_results; index++)
    {
        BSL_AbsSecBlock_AddResult(sec_blk->abs_sec_blk, BSL_SecResultList_cget(outcome->result_list, index));
    }
    size_t n_params = BSL_SecParamList_size(outcome->param_list);
    for (index = 0; index < n_params; index++)
    {
        BSL_AbsSecBlock_AddParam(sec_blk->abs_sec_blk, BSL_SecParamList_cget(outcome->param_list, index));
    }

    BSL_Data_Deinit(&sec_blk->btsd);
    BSL_Data_InitBuffer(&sec_blk->btsd, 500 + ((n_params + n_results) * 100));
    int encode_result = BSL_AbsSecBlock_EncodeToCBOR(sec_blk->abs_sec_blk, sec_blk->btsd);
    if (encode_result <= 0)
    {
        BSL_LOG_ERR("Failed to encode ASB");
        return -999;
    }
    else
    {
        sec_blk->btsd.len = (size_t)encode_result;
        sec_blk->btsd.ptr = realloc(sec_blk->btsd.ptr, sec_blk->btsd.len);
    }
    return 0;
}

int BSL_ExecBIBAccept(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleCtx_t *bundle,
                      BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    assert(lib != NULL);
    assert(bundle != NULL);
    assert(BSL_SecOper_IsConsistent(sec_oper));
    assert(BSL_SecOutcome_IsConsistent(outcome));

    const BSL_BundleBlock_t *sec_blk = BSL_BundleCtx_GetBlockById((BSL_BundleCtx_t *)bundle, sec_oper->sec_block_num);
    if (sec_blk->abs_sec_blk == NULL)
    {
        ((BSL_BundleBlock_t *)sec_blk)->abs_sec_blk = BSL_MALLOC(sizeof(*sec_blk->abs_sec_blk));
        BSL_AbsSecBlock_InitEmpty(sec_blk->abs_sec_blk);
    }
    if (BSL_AbsSecBlock_DecodeFromCBOR(sec_blk->abs_sec_blk, sec_blk->btsd) < 0)
    {
        BSL_LOG_ERR("Failed to parse ASB CBOR");
        return -9912;
    }
    BSL_AbsSecBlock_Print(sec_blk->abs_sec_blk);
    size_t i;
    for (i = 0; i < BSL_SecParamList_size(sec_blk->abs_sec_blk->params); i++)
    {
        const BSL_SecParam_t *param = BSL_SecParamList_cget(sec_blk->abs_sec_blk->params, i);
        BSL_SecParamList_push_back(sec_oper->_param_list, *param);
    }
    const int res = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (res != 0 || outcome->is_success == false)
    {
        BSL_LOG_ERR("BIB Acceptor failed!");
        return -1;
    }
    if (!BSL_AbsSecBlock_IsResultEqual(sec_blk->abs_sec_blk, outcome))
    {
        BSL_LOG_ERR("BIB VERIFICATION FAILED");
        return -99929;
    }
    BSL_LOG_INFO("BIB Validation passed");
    if (BSL_SecOper_IsRoleAccepter(sec_oper))
    {
        int status = BSL_AbsSecBlock_StripResults(sec_blk->abs_sec_blk, outcome);
        if (status < 0)
        {
            BSL_LOG_ERR("Failure to strip ASB of results");
            return -9;
        }

        if (BSL_AbsSecBlock_IsEmpty(sec_blk->abs_sec_blk))
        {
            BSL_BundleCtx_RemoveBlock(bundle, sec_blk->blk_num);
            sec_blk = NULL;
        }
    }
    return 0;
}

int BSL_ExecBCBSource(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleCtx_t *bundle,
                      BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    (void)lib;
    assert(bundle != NULL);
    assert(sec_oper != NULL);
    assert(outcome != NULL);
    int blk_id;
    if ((blk_id = BSL_BundleCtx_CreateBlock((BSL_BundleCtx_t *)bundle, BSL_SECBLOCKTYPE_BCB)) < 0)
    {
        BSL_LOG_ERR("Could not prepare security context execution as security source");
        return -1;
    }
    sec_oper->sec_block_num = (uint64_t)blk_id;
    const int res           = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (res != 0 || outcome->is_success == false)
    {
        BSL_LOG_ERR("BCB Source failed!");
        return -1;
    }

    BSL_BundleBlock_t *sec_blk =
        (BSL_BundleBlock_t *)BSL_BundleCtx_GetBlockById((BSL_BundleCtx_t *)bundle, sec_oper->sec_block_num);
    assert(sec_blk->abs_sec_blk != NULL);
    sec_blk->abs_sec_blk->sec_context_id = sec_oper->context_id;
    BSL_AbsSecBlock_AddTarget(sec_blk->abs_sec_blk, sec_oper->target_block_num);

    size_t index;
    size_t n_results = BSL_SecResultList_size(outcome->result_list);
    for (index = 0; index < n_results; index++)
    {
        BSL_AbsSecBlock_AddResult(sec_blk->abs_sec_blk, BSL_SecResultList_cget(outcome->result_list, index));
    }
    size_t n_params = BSL_SecParamList_size(outcome->param_list);
    for (index = 0; index < n_params; index++)
    {
        BSL_AbsSecBlock_AddParam(sec_blk->abs_sec_blk, BSL_SecParamList_cget(outcome->param_list, index));
    }

    BSL_Data_Deinit(&sec_blk->btsd);
    BSL_Data_InitBuffer(&sec_blk->btsd, 500 + ((n_params + n_results) * 100));
    int encode_result = BSL_AbsSecBlock_EncodeToCBOR(sec_blk->abs_sec_blk, sec_blk->btsd);
    if (encode_result <= 0)
    {
        BSL_LOG_ERR("Failed to encode ASB");
        return -999;
    }
    else
    {
        sec_blk->btsd.len = (size_t)encode_result;
        sec_blk->btsd.ptr = realloc(sec_blk->btsd.ptr, sec_blk->btsd.len);
    }
    return 0;
}

int BSL_SecCtx_ExecutePolicyActionSetNew(BSL_LibCtx_t *lib, BSL_PolicyResponseSet_t *output_response, BSL_BundleCtx_t *bundle,
                                         const BSL_PolicyActionSet_t *action_set)
{
    assert(lib != NULL);
    assert(output_response != NULL);
    // assert(BSL_AssertZeroed(output_response, sizeof(*output_response)));
    assert(BSL_PolicyActionSet_IsConsistent(action_set));
    assert(bundle != NULL);

    /**
     * Notes:
     *  - It should evaluate every security operation, even if earlier ones failed.
     *  - The outcome can indicate in the policy action response how exactly it fared (pass, fail, etc)
     *  - BCB will be a special case, since it actively manipulates the BTSD
     * 
     */
    for (size_t sec_oper_index = 0; sec_oper_index < BSL_PolicyActionSet_CountSecOpers(action_set); sec_oper_index++)
    {
        BSL_LOG_INFO("Trying sec operation index %lu", sec_oper_index);
    }

    assert(BSL_PolicyResponseSet_IsConsistent(output_response));
    return 0;
}

int BSL_SecCtx_ExecutePolicyActionSet(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, BSL_PolicyActionSet_t *action_set)
{
    assert(BSL_PolicyActionSet_IsConsistent(action_set));
    CHKERR1(lib);
    CHKERR1(bundle);

    size_t fail_count = 0;

    size_t sec_oper_count = BSL_PolicyActionSet_CountSecOpers(action_set);
    for (size_t secoper_index=0; secoper_index < sec_oper_count; secoper_index++)
    {
        /// FIXME(BVB) This should be refactored to be const-correct
        BSL_SecOper_t *sec_oper = (BSL_SecOper_t *)BSL_PolicyActionSet_GetSecOperAtIndex(action_set, secoper_index);
        
        BSL_LOG_DEBUG("Evaluating BSL_SecOper");
        const BSL_SecCtxDesc_t *scd = BSL_SecCtxDict_cget(lib->sc_reg, sec_oper->context_id);
        if (!scd)
        {
            // Special case which should not happen
            BSL_LOG_ERR("Failed to lookup Security Context ID %" PRId64, sec_oper->context_id);
            return -2;
        }

        BSL_SecOutcome_t outcome;
        BSL_SecOutcome_Init(&outcome, sec_oper, 100000);
        int errcode = -1;
        if (BSL_SecOper_IsBIB(sec_oper))
        {
            errcode = BSL_SecOper_IsRoleSource(sec_oper) == true
                            ? BSL_ExecBIBSource(scd->execute, lib, (BSL_BundleCtx_t *)bundle, sec_oper, &outcome)
                            : BSL_ExecBIBAccept(scd->execute, lib, (BSL_BundleCtx_t *)bundle, sec_oper, &outcome);
        }
        else
        {
            if (BSL_SecOper_IsRoleSource(sec_oper))
            {
                errcode = BSL_ExecBCBSource(scd->execute, lib, (BSL_BundleCtx_t *)bundle, sec_oper, &outcome);
            }
            else
            {
                errcode = -99;
            }
        }
        // BSL_SecOper_Deinit(sec_oper);
        BSL_SecOutcome_Deinit(&outcome);

        if (errcode != 0)
        {
            fail_count += 1;
            BSL_LOG_ERR("Security Op failed: %ld", errcode);
            break;
        }

    }
    return fail_count == 0 ? 0 : -1;
}

int BSL_SecCtx_ExecutePolicyActionDeprecated(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, BSL_PolicyActionDeprecated_t *act)
{
    CHKERR1(lib);
    CHKERR1(bundle);
    CHKERR1(act);

    size_t fail_count = 0;
    while (BSL_SecOperList_size(act->sec_oper_list) > 0)
    {
        BSL_SecOper_t sec_oper_full = *BSL_SecOperList_get(act->sec_oper_list, 0);
        BSL_SecOper_t *sec_oper = &sec_oper_full;
        {
            // Pop from the front of the list
            size_t size0 = BSL_SecOperList_size(act->sec_oper_list);
            assert(size0 > 0);
            BSL_SecOperList_it_t sec_oper_iter;
            BSL_SecOperList_it(sec_oper_iter, act->sec_oper_list);
            BSL_SecOperList_remove(act->sec_oper_list, sec_oper_iter);
            assert(BSL_SecOperList_size(act->sec_oper_list) == size0 - 1);
        }

        BSL_LOG_DEBUG("Evaluating BSL_SecOper");
        const BSL_SecCtxDesc_t *scd = BSL_SecCtxDict_cget(lib->sc_reg, sec_oper->context_id);
        if (!scd)
        {
            // Special case which should not happen
            BSL_LOG_ERR("Failed to lookup Security Context ID %" PRId64, sec_oper->context_id);
            return -2;
        }

        BSL_SecOutcome_t outcome;
        BSL_SecOutcome_Init(&outcome, sec_oper, 100000);
        int errcode = -1;
        if (BSL_SecOper_IsBIB(sec_oper))
        {
            errcode = BSL_SecOper_IsRoleSource(sec_oper) == true
                            ? BSL_ExecBIBSource(scd->execute, lib, (BSL_BundleCtx_t *)bundle, sec_oper, &outcome)
                            : BSL_ExecBIBAccept(scd->execute, lib, (BSL_BundleCtx_t *)bundle, sec_oper, &outcome);
        }
        else
        {
            if (BSL_SecOper_IsRoleSource(sec_oper))
            {
                errcode = BSL_ExecBCBSource(scd->execute, lib, (BSL_BundleCtx_t *)bundle, sec_oper, &outcome);
            }
            else
            {
                errcode = -99;
            }
        }
        BSL_SecOper_Deinit(sec_oper);
        BSL_SecOutcome_Deinit(&outcome);

        if (errcode != 0)
        {
            fail_count += 1;
            BSL_LOG_ERR("Security Op failed: %ld", errcode);
            break;
        }
    }
    return fail_count == 0 ? 0 : -1;
}