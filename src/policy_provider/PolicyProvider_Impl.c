/**
 * @file
 * @brief Concrete implementation of example Policy Provider using BSL front-end
 * @ingroup example_pp
 */
#include <PolicyProvider.h>
#include "SamplePolicyProvider.h"

bool BSL_PolicyActionSet_IsConsistent(const BSL_PolicyActionSet_t *self)
{
    assert(self != NULL);
    assert(self->capacity > 0);
    assert(self->capacity == sizeof(self->sec_operations) / sizeof(BSL_SecOper_t));
    assert(self->size <= self->capacity);
    // TODO, make sure every element in the array that 
    // is not a sec oper is set to all zeros.
    return true;
}

size_t BSL_PolicyActionSet_StructSizeBytes(void)
{
    return sizeof(BSL_PolicyActionSet_t);
}

void BSL_PolicyActionSet_Deinit(BSL_PolicyActionSet_t *self)
{
    assert(self != NULL);
    assert(BSL_PolicyActionSet_IsConsistent(self));
    for (size_t operation_index=0; operation_index < self->size; operation_index++)
    {
        BSL_SecOper_Deinit(&(self->sec_operations[operation_index]));
    }
    memset(self, 0, sizeof(*self));
}

size_t BSL_PolicyActionSet_CountSecOpers(const BSL_PolicyActionSet_t *self)
{
    assert(BSL_PolicyActionSet_IsConsistent(self));
    return self->size;
}

const BSL_SecOper_t *BSL_PolicyActionSet_GetSecOperAtIndex(const BSL_PolicyActionSet_t *self, size_t index)
{
    assert(BSL_PolicyActionSet_IsConsistent(self));
    assert(index < BSL_PolicyActionSet_CountSecOpers(self));
    assert(index < self->capacity);
    const BSL_SecOper_t *sec_oper = &self->sec_operations[index];
    assert(BSL_SecOper_IsConsistent(sec_oper));
    return sec_oper;
}

size_t BSL_PolicyActionSet_GetErrCode(const BSL_PolicyActionSet_t *self)
{
    assert(BSL_PolicyActionSet_IsConsistent(self));
    return self->err_code;
}

bool BSL_PolicyResponseSet_IsConsistent(const BSL_PolicyResponseSet_t *self)
{
    assert(self != NULL);
    assert(self->err_msg[sizeof(self->err_msg) - 1] == '\0');
    assert(strlen(self->err_msg) < sizeof(self->err_msg));
    return true;
}

void BSL_PolicyResponseSet_Init(BSL_PolicyResponseSet_t *self, size_t noperations, size_t nfailed)
{
    assert(self != NULL);
    assert(BSL_AssertZeroed(self, sizeof(*self)));
    self->failure_count = nfailed;
    self->total_operations = noperations;
    self->err_code = (nfailed == 0 && noperations > 1) ? 0 : 1;
}
void BSL_PolicyResponseSet_Deinit(BSL_PolicyResponseSet_t *self)
{
    assert(BSL_PolicyResponseSet_IsConsistent(self));
    memset(self, 0, sizeof(*self));
}

size_t BSL_PolicyResponseSet_CountResponses(const BSL_PolicyResponseSet_t *self)
{
    assert(BSL_PolicyResponseSet_IsConsistent(self));
    return 1; // TODO fix this.
}

void BSL_PolicyProvider_Deinit(BSL_PolicyProvider_t *self)
{
    assert(BSL_PolicyProvider_IsConsistent(self));
    for (size_t index = 0; index < self->rule_count; index++)
    {
        BSLP_PolicyRule_Deinit(&self->rules[index]);
    }
    memset(self, 0, sizeof(*self));
}

bool BSL_PolicyProvider_IsConsistent(const BSL_PolicyProvider_t *self)
{
    assert(self != NULL);
    assert(strlen(self->name) < sizeof(self->name)); // TODO - Safer strlen since no strnlen
    assert(self->rule_capacity == (sizeof(self->rules) / sizeof(BSLP_PolicyRule_t)));
    assert(self->rule_count < self->rule_capacity);
    return true;
}

/**
 * Note that criticality is HIGH
 */
int BSL_PolicyProvider_InspectActions(const BSL_PolicyProvider_t *self, BSL_PolicyActionSet_t *output_action_set, const BSL_BundleCtx_t *bundle, BSL_PolicyLocation_e location)
{
    // This is an output struct. The caller only provides the allocation for it (which must be zero)
    assert(BSL_AssertZeroed(output_action_set, sizeof(*output_action_set)));
    assert(BSL_PolicyProvider_IsConsistent(self));

    memset(output_action_set, 0, sizeof(*output_action_set));
    output_action_set->capacity = sizeof(output_action_set->sec_operations) / sizeof(BSL_SecOper_t);
    for (size_t index = 0; index < self->rule_count && index < self->rule_capacity; index++)
    {
        const BSLP_PolicyRule_t *rule = &self->rules[index];
        assert(BSLP_PolicyRule_IsConsistent(rule));

        // Only do accept/verify for now
        assert(rule->role != BSL_SECROLE_SOURCE);
        if (BSLP_PolicyPredicate_IsMatch(&rule->predicate, location, BSL_BundleCtx_GetSrcEID(bundle), BSL_BundleCtx_GetDstEID(bundle)))
        {
            ssize_t target_block_num = -1;
            ssize_t security_block_num = -1;
            if (rule->target_block_type == BSL_BLOCK_TYPE_PRIMARY)
            {
                target_block_num = 0;
            }
            for (size_t block_index = 0; block_index < 100; block_index++)
            {
                // TODO - Need a BSL_BundleCtx_GetBlockMetadataByIndex
                size_t block_type = 0;
                if (0 == BSL_BundleContext_GetBlockMetadata(bundle, block_index, &block_type, NULL, NULL, NULL)) 
                {
                    if (block_type == rule->sec_block_type)
                    {
                        security_block_num = block_index;
                    }
                    if (block_type == rule->target_block_type)
                    {
                        target_block_num = block_index;
                    }
                }
            }
            if (target_block_num >= 0 && security_block_num > 1)
            {
                BSL_SecOper_t *sec_oper = &output_action_set->sec_operations[output_action_set->size++];
                output_action_set->err_code += BSLP_PolicyRule_EvaluateAsSecOper(rule, sec_oper, bundle, location);
            }
            else
            {
                BSL_LOG_ERR("Cannot make SecOper from policy rule: target_block_num=%ld, sec_block_num=%ld", target_block_num, security_block_num);
                output_action_set->err_code++;
            }
        }
    }

    assert(BSL_PolicyActionSet_IsConsistent(output_action_set));
    return output_action_set->err_code;
}

int BSL_PolicyProvider_FinalizeActions(const BSL_PolicyProvider_t *self, BSL_PolicyResponseSet_t *response_output, BSL_BundleCtx_t *bundle, const BSL_PolicyActionSet_t *policy_actions)
{
    (void)self;
    (void)bundle;
    (void)policy_actions;
    BSL_PolicyResponseSet_t temp = {0};
    (void)response_output;
    (void)temp;
    assert(false); // Unimplemented

    // Really, this will just call BSL_SecurityContext_Execute for each
    return 0;
}
