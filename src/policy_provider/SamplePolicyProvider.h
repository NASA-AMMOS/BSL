/**
 * @file
 * @brief Spec of locally-defined data structures.
 * @ingroup example_pp
 */
#ifndef BSLP_SAMPLE_POLICY_PROVIDER_H
#define BSLP_SAMPLE_POLICY_PROVIDER_H

#include <stdint.h>

#include <BPSecLib.h>

// Provide concrete definitions of forward-declared types in front-end API.


/// @brief Contains the populated security operations for this bundle.
/// @note This is intended to be a write-once, read-only struct
struct BSL_PolicyActionSet_s {
    BSL_SecOper_t   sec_operations [10];
    size_t          size;
    size_t          capacity;
    int             err_code;
};

/// @brief Contains the results and outcomes after performing the security operations.
/// @note This struct is still in-concept
struct BSL_PolicyResponseSet_s {
    /// @brief This maps to the sec_operations in BSL_PolicyActionSet, 
    ///        and contains the result code of that security operation.
    int             results [10];
    char            err_msg[256];
    int             err_code;
    size_t          total_operations;
    size_t          failure_count;
};

/**
 * THE key function that matches a bundle against a rule to provide the output action and specific parameters to use for the security operation.
 * 
 * E.g., it'll give parameters like which key to use, but also parameters for target block, security block, sec context, etc.
 */
typedef struct {
    BSL_PolicyLocation_e    location;
    BSL_HostEIDPattern_t    src_eid_pattern;
    BSL_HostEIDPattern_t    secsrc_eid_pattern;
    BSL_HostEIDPattern_t    dst_eid_pattern;
} BSLP_PolicyPredicate_t;

/**
 * @brief Initialize this policy predicate
 * 
 * A policy predicate represents a way to match whether a rule applies to a bundle.
 * 
 * @param[in] self This predicate
 * @param[in] location BSL_PolicyLocation_e location in the BPA
 * @param[in] src_eid_pattern Host-defined EID pattern to match for
 * @param[in] srcsrc_eid_pattern Host-defined EID pattern for SECURITY SOURCE in security block
 * @param[in] dst_eid_pattern Host-defined EID pattern for DESTINATION EID
 * 
 * @returns Nothing
 */
void BSLP_PolicyPredicate_Init(BSLP_PolicyPredicate_t *self,
                               BSL_PolicyLocation_e location,
                               BSL_HostEIDPattern_t src_eid_pattern,
                               BSL_HostEIDPattern_t secsrc_eid_pattern,
                               BSL_HostEIDPattern_t dst_eid_pattern);

/**
 * @brief Returns true if the given predicate matches the arguments
 * 
 * @param[in] self This predicate
 * @param[in] location Location in the BPA
 * @param[in] src_eid Source EID
 * @param[in] dst_eid Destination EID
 */
bool BSLP_PolicyPredicate_IsMatch(const BSLP_PolicyPredicate_t *self, BSL_PolicyLocation_e location, BSL_HostEID_t src_eid, BSL_HostEID_t dst_eid);

/**
 * @brief Returns true if this is in a consistent and sane state
 * 
 * @param[in] self This predicate.
 * @returns True if sane and consistent.
 */
bool BSLP_PolicyPredicate_IsConsistent(const BSLP_PolicyPredicate_t *self);

/**
 * @brief Represents a policy rule
 * 
 * A policy rule contains parameters and other metadata
 * necessary to create populated Security Operations for
 * a given bundle. 
 * 
 * It first contains a predicate, which is used to identify
 * whether this rule applies to a given bundle.
 * 
 * It then uses the other fields to create and populate security
 * operations with details (type, role, parameter values, etc.)
 */
typedef struct BSLP_PolicyRule_s {
    char                        description [120];
    BSLP_PolicyPredicate_t      predicate;
    BSL_SecRole_e               role;
    BSL_SecParamList_t          params;
    BSL_BundleBlockTypeCode_e   target_block_type;
    BSL_SecBlockType_e          sec_block_type;
    uint64_t                    context_id;
} BSLP_PolicyRule_t;

/**
 * @brief Initialize this policy rule
 * 
 * @param[in] self This policy rule
 * @param[in] dest Description of this rule (C-string)
 * @param[in] predicate Predicate used to identify which bundles apply
 * @param[in] context_id Security context ID
 * @param[in] role Such as source, acceptor, etc
 * @param[in] sec_block_type Block type (BIB or BCB)
 * @param[in] target_block_type Target block type (anything, such as primary or payload)
 * 
 * @returns Zero on success
 */
int BSLP_PolicyRule_Init(BSLP_PolicyRule_t *self, const char *desc, BSLP_PolicyPredicate_t predicate, uint64_t context_id,
                         BSL_SecRole_e role, BSL_SecBlockType_e sec_block_type, BSL_BundleBlockTypeCode_e target_block_type);

/**
 * @brief Returns true if internal state is consistent and sane
 * 
 * @param[in] self This rule
 * 
 * @returns True if sane
 */
bool BSLP_PolicyRule_IsConsistent(const BSLP_PolicyRule_t *self);

/**
 * @brief De-initialize, release any resources, and zero this struct.
 * 
 * @param[in] self This rule
 */
void BSLP_PolicyRule_Deinit(BSLP_PolicyRule_t *self);

/**
 * @brief Include a BPSec parameter to this rule. Used immediately after Init.
 * 
 * @param[in] self This rule
 * @param[in] param Pointer to the Parameter.
 */
void BSLP_PolicyRule_AddParam(BSLP_PolicyRule_t *self, const BSL_SecParam_t *param);

/**
 * @brief Critical function creating a security operation from a bundle and location.
 * 
 * @param[in] self This policy rule
 * @param[in] sec_oper @preallocated Caller-allocated space for the output security action.
 * @param[in] bundle Bundle to test match against
 * @param[in] location Location in the BPA
 *
 * @return Zero on success, negative on failure. 
 */
int BSLP_PolicyRule_EvaluateAsSecOper(const BSLP_PolicyRule_t *self, BSL_SecOper_t *sec_oper, const BSL_BundleCtx_t *bundle, BSL_PolicyLocation_e location);

/// @brief Concrete definition of the BSL_PolicyProvider_t
struct BSL_PolicyProvider_s {
    char                name [100];
    BSLP_PolicyRule_t   rules [100];
    size_t              rule_count;
    size_t              rule_capacity;
};

#endif // BSLP_SAMPLE_POLICY_PROVIDER_H
