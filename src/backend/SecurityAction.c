#include "SecurityAction.h"

size_t BSL_SecurityAction_Sizeof(void)
{
    return sizeof(BSL_SecurityAction_t);
}

bool BSL_SecurityAction_IsConsistent(const BSL_SecurityAction_t *self)
{
    (void) self;
    return true;
}

void BSL_SecurityAction_Init(BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);

    BSL_SecOperList_init(self->sec_op_list);
    self->err_ct = 0;
}

void BSL_SecurityAction_Deinit(BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);

    BSL_SecOperList_clear(self->sec_op_list);
}

void BSL_SecurityAction_IncrError(BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);
    self->err_ct++;
}

size_t BSL_SecurityAction_CountErrors(const BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);
    return self->err_ct;
}

int BSL_SecurityAction_AppendSecOper(BSL_SecurityAction_t *self, BSL_SecOper_t *sec_oper)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(self->sec_op_list);
    size_t i;
    for (i = 0 ; i < BSL_SecOperList_size(self->sec_op_list); i ++)
    {
        BSL_SecOper_t *comp = BSL_SecOperList_get(self->sec_op_list, i);
        if (BSL_SecOper_GetTargetBlockNum(comp) == BSL_SecOper_GetTargetBlockNum(sec_oper))
        {
            // SOURCE BIB or ACCEPT BCB should come first
            // true if ACC BIB or SRC BCB
            if (BSL_SecOper_IsBIB(sec_oper) ^ BSL_SecOper_IsRoleSource(sec_oper))
            {
                BSL_SecOperList_push_at(self->sec_op_list, i+1, *sec_oper);
            }
            else
            {
                BSL_SecOperList_push_at(self->sec_op_list, i, *sec_oper);
            }
            break;
        }

        // security operation in list targets security operation
        if (BSL_SecOper_GetTargetBlockNum(comp) == BSL_SecOper_GetSecurityBlockNum(sec_oper))
        {
            BSL_SecOperList_push_at(self->sec_op_list, i, *sec_oper);
            break;
        }

        // new security operation targets security operation in list
        if (BSL_SecOper_GetTargetBlockNum(sec_oper) == BSL_SecOper_GetSecurityBlockNum(comp))
        {
            BSL_SecOperList_push_at(self->sec_op_list, i+1, *sec_oper);
            break;
        }

        // same security block number, order by target
        if (BSL_SecOper_GetSecurityBlockNum(sec_oper) == BSL_SecOper_GetSecurityBlockNum(comp))
        {
            if (BSL_SecOper_GetTargetBlockNum(comp) - BSL_SecOper_GetTargetBlockNum(sec_oper))
            {
                BSL_SecOperList_push_at(self->sec_op_list, i, *sec_oper);
            }
            else
            {
                BSL_SecOperList_push_at(self->sec_op_list, i+1, *sec_oper);
            }
            break;
        }
    }

    if (i >= BSL_SecOperList_size(self->sec_op_list))
    {
        BSL_SecOperList_push_back(self->sec_op_list, *sec_oper);
    }
    
    return BSL_SUCCESS;
}

size_t BSL_SecurityAction_CountSecOpers(const BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(self->sec_op_list);
    return BSL_SecOperList_size(self->sec_op_list);
}

BSL_SecOper_t *BSL_SecurityAction_GetSecOperAtIndex(const BSL_SecurityAction_t *self, size_t index)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(self->sec_op_list);
    return BSL_SecOperList_get(self->sec_op_list, index);
}