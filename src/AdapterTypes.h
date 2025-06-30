#ifndef BSL_ADAPTER_TYPES_H
#define BSL_ADAPTER_TYPES_H

#include "BPSecTypes.h"
#include "DataContainers.h"

/** Represents the output following execution of a security operation.
 */
typedef struct BSL_SecOutcome_s
{
    /// @brief Boolean indicating true when successful
    bool is_success;

    /// @brief Pre-allocated memory pool, lifetimes of all results and parameters are tied to this.
    BSL_Data_t allocation;

    /// @brief Non-NULL pointer to Security Operation that provided the input.
    const BSL_SecOper_t *sec_oper;

    /// @brief List of security parameters with metadata for receiver. Must be encoded into the BTSD.
    BSL_SecParamList_t param_list;

    /// @brief List of security results with metadata for receiver. Must be encoded into BTSD.
    BSL_SecResultList_t result_list;
} BSL_SecOutcome_t;

/** Populate a pre-allocated security outcome struct.
 *
 * @param self Non-Null pointer to this security outcome.
 * @param sec_oper
 * @param allocation_size Size of working space to allocate.
 */
void BSL_SecOutcome_Init(BSL_SecOutcome_t *self, const BSL_SecOper_t *sec_oper, size_t allocation_size);

/** Release any resources owned by this security outcome.
 *
 * @param self Non-Null pointer to this security outcome.
 */
void BSL_SecOutcome_Deinit(BSL_SecOutcome_t *self);

/** Return true if internal invariants hold
 * 
 * @param self This sec outcome.
 * @return true if invariants hold
 */
bool BSL_SecOutcome_IsConsistent(const BSL_SecOutcome_t *self);

/** Append a Security Result to this outcome.
 *
 * @todo Double-check copy semantics.
 *
 * @param self Non-NULL pointer to this security outcome.
 * @param sec_result Non-NULL pointer to security result to copy and append.
 */
void BSL_SecOutcome_AppendResult(BSL_SecOutcome_t *self, const BSL_SecResult_t *sec_result);

/** Get the result at index i. Panics if i is out of range.
 * 
 * @param self This outcome
 * @param index Index in the list to retrieve
 */
const BSL_SecResult_t *BSL_SecOutcome_GetResultAtIndex(const BSL_SecOutcome_t *self, size_t index);

/** Get the number of results
 * 
 * @param self this sec outcome
 */
size_t BSL_SecOutcome_GetResultCount(const BSL_SecOutcome_t *self);

/** Append a Security Parameter to this outcome.
 *
 * @todo Double-check copy semantics.
 *
 * @param self Non-NULL pointer to this security outcome.
 * @param param Non-NULL pointer to security parameter to copy and append.
 */
void BSL_SecOutcome_AppendParam(BSL_SecOutcome_t *self, const BSL_SecParam_t *param);

#endif /* BSL_ADAPTER_TYPES_H */
