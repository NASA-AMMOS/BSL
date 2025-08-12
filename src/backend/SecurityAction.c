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
    self->sec_op_list_length = 0;
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

    BSL_SecOperList_it_t it;

    for (BSL_SecOperList_it(it, self->sec_op_list); !BSL_SecOperList_end_p(it); BSL_SecOperList_next(it))
    {
        // New sec block shares target with another sec block
        if (BSL_SecOper_GetTargetBlockNum(BSL_SecOperList_cref(it)) == BSL_SecOper_GetTargetBlockNum(sec_oper))
        {
            bool before = !(BSL_SecOper_IsBIB(sec_oper) ^ BSL_SecOper_IsRoleSource(sec_oper));
            if (before)
            {                
                // It seems the m*lib docs is incorrect here -
                // it states that an uninitialized it2 = insert at front, but it was causing errors
                // So, let's use a simple bool and check

                // TODO BEFORE
                BSL_SecOperList_previous(it);
                BSL_SecOperList_push_after(BSL_SecOperList_ref(it), sec_oper);
                BSL_SecOperList_next(it);
            }
            else
            {
                BSL_SecOperList_push_after(BSL_SecOperList_ref(it), sec_oper);
            }

            if (!(BSL_SecOper_IsBIB(BSL_SecOperList_cref(it)) ^ BSL_SecOper_IsBIB(sec_oper)))
            {
                BSL_SecOper_SetConclusion(sec_oper, BSL_SECOP_CONCLUSION_INVALID);
            }
           
            self->sec_op_list_length ++;
            return BSL_SUCCESS;
        }

        // New sec block is the target of another sec block
        if (BSL_SecOper_GetTargetBlockNum(BSL_SecOperList_cref(it)) == BSL_SecOper_GetSecurityBlockNum(sec_oper))
        {
            BSL_SecOperList_previous(it);
            BSL_SecOperList_push_after(BSL_SecOperList_ref(it), sec_oper);
            BSL_SecOperList_next(it);
            self->sec_op_list_length ++;
            return BSL_SUCCESS;
        }

        // New sec block targets a block already in list
        if (BSL_SecOper_GetTargetBlockNum(sec_oper) == BSL_SecOper_GetSecurityBlockNum(BSL_SecOperList_cref(it)))
        {
            BSL_SecOperList_push_after(BSL_SecOperList_ref(it), sec_oper);
            self->sec_op_list_length ++;
            return BSL_SUCCESS;
        }
    }

    // Target not shared, order doesn't matter
    BSL_SecOperList_push_back(self->sec_op_list, sec_oper);
    self->sec_op_list_length ++;

    return BSL_SUCCESS;
}

size_t BSL_SecurityAction_CountSecOpers(const BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);
    return self->sec_op_list_length;
}

BSL_SecOper_t *BSL_SecurityAction_GetSecOperAtIndex(const BSL_SecurityAction_t *self, size_t index)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(self->sec_op_list);
    size_t n = 0;
    for M_EACH(item, self->sec_op_list, ILIST_OPLIST(BSL_SecOperList)) {
        if (n == index)
        {
            return item;
        }
        n++;
    }
    return NULL;
}