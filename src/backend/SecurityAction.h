#include <m-array.h>
#include <BPSecLib_Private.h>
#include "SecOperation.h"

// NOLINTBEGIN
ARRAY_DEF(BSL_SecOperList, BSL_SecOper_t, M_OPEXTEND(M_POD_OPLIST, CLEAR(API_2(BSL_SecOper_Deinit))))
// NOLINTEND

struct BSL_SecurityAction_s
{
    BSL_SecOperList_t sec_op_list;
    size_t err_ct;
};
