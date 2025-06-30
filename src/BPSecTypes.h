/*
 * Copyright (c) 2024 The Johns Hopkins University Applied Physics
 * Laboratory LLC.
 *
 * This file is part of the Bundle Protocol Security Library (BSL).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This work was performed for the Jet Propulsion Laboratory, California
 * Institute of Technology, sponsored by the United States Government under
 * the prime contract 80NM0018D0004 between the Caltech and NASA under
 * subcontract 1700763.
 */
/** @file
 * Structures and definitions for primitves used to compose BPSec operations and results.
 * @ingroup frontend
 */

#ifndef BSL_BPSECTYPES_H_
#define BSL_BPSECTYPES_H_

#include <assert.h>
#include <stdint.h>

#include <m-list.h>

#include "DataContainers.h"

#define BSL_DEFAULT_BYTESTR_LEN (128)

/**
 * @todo - Possibly belongs in policy?
 */
typedef enum
{
    BSL_SECROLE_SOURCE,
    BSL_SECROLE_VERIFIER,
    BSL_SECROLE_ACCEPTOR
} BSL_SecRole_e;

/**
 * RFC 9172-specified block type codes for BIB and BCB.
 */
typedef enum
{
    BSL_SECBLOCKTYPE_BIB = 11,
    BSL_SECBLOCKTYPE_BCB = 12
} BSL_SecBlockType_e;

#define BSL_SecBlockType_IsSecBlock(block_id) \
    (((block_id) >= BSL_SECBLOCKTYPE_BIB) && ((block_id) <= BSL_SECBLOCKTYPE_BCB))

/**
 * Represents a security result, being a 2-tuple of (result-id, bytes).
 *
 * Comes with extra data fields for convenience when processing.
 */
typedef struct BSL_SecResult_s
{
    /// @brief Result ID, which is context depdendent, based on security context.
    uint64_t result_id;

    /// @brief Context ID, put in here for convenience.
    uint64_t context_id;

    /// @brief Target block id, put in here for convenience.
    uint64_t target_block_num;

    /// @brief Result as byte array, up to a given maximum
    uint8_t _bytes[BSL_DEFAULT_BYTESTR_LEN + 1];

    /// @brief Length of data (in bytes) of the contained bytestring. Always less than BSL_DEFAULT_BYTESTR_LEN.
    size_t _bytelen;
} BSL_SecResult_t;

/** Populate a pre-allocated SecResult.
 *
 * @param self Non-NULL pointer to allocated result.
 * @param result_id Result ID of corresponding result bytestring, meaning dependent on security context.
 * @param context_id ID of security context.
 * @param target_block_num Target of the given security result, included here for convenience.
 * @param content Read-only view to data containing the bytes of the security result, which is copied out of here.
 */
int BSL_SecResult_Init(BSL_SecResult_t *self, uint64_t result_id, uint64_t context_id, uint64_t target_block_num,
                       BSL_Data_t content);

/** Return true when internal invariant checks pass
 * 
 * @param self This security result
 */
bool BSL_SecResult_IsConsistent(const BSL_SecResult_t *self);

/** Helper to get the result as a BSL_Data_t
 * @param self This sec result
 */
BSL_Data_t BSL_SecResult_ResultAsData(const BSL_SecResult_t *self);

// NOLINTBEGIN
LIST_DEF(BSL_SecResultList, BSL_SecResult_t, M_POD_OPLIST)
// NOLINTEND

/**
 * Security parameters defined in RFC9172 may be unsigned integers or bytestrings
 */
enum BSL_SecParam_Types_e
{
    /// @brief Inidcates parsed value not of expected type.
    BSL_SECPARAM_TYPE_UNKNOWN = 0,

    /// @brief Indicates value type is an unsigned integer.
    BSL_SECPARAM_TYPE_INT64,

    /// @brief Indicates the value type is a byte string.
    BSL_SECPARAM_TYPE_BYTESTR,
};

/** Defines supplementary Security Paramter type used internally by
 * this implementation for testing or additional policy provider information.
 * @todo - Maybe move to SecurityContext.h
 */
typedef enum
{
    /// @brief Do not use. Indicates start index of internal param ids.
    BSL_SECPARAM_TYPE_INT_STARTINDEX = 1000,

    /// @brief Used to pass in a key id found in the key registry.
    BSL_SECPARAM_TYPE_INT_KEY_ID,

    /// @brief Used by tests to pass in a specific key bytestring
    BSL_SECPARAM_TYPE_INT_FIXED_KEY,

    /// @brief Do not use. Indicates final index of internal param ids.
    BSL_SECPARAM_TYPE_INT_ENDINDEX
} BSL_SecParam_InternalIds;

/** Represents a security parameter in an ASB as defined in RFC9172.
 *
 * In an encoded ASB, these are tuples of (param-id, param-val)
 *
 */
typedef struct BSL_SecParam_s
{
    /// @brief Parameter ID
    uint64_t param_id;

    /// @brief Private. Indicates whether this is an integer or bytestring.
    enum BSL_SecParam_Types_e _type;

    /// @brief Private. When an integer, this field is populated with the correct value.
    uint64_t _uint_value;

    /// @brief Private. When a bytestring, this field is set, with the _bytelen set accordingly.
    uint8_t _bytes[BSL_DEFAULT_BYTESTR_LEN + 1];

    /// @brief Private. When a bytestring, this field is the length of param, and always less than
    /// BSL_DEFAULT_BYTESTR_LEN.
    size_t _bytelen;
} BSL_SecParam_t;

/** Return true if invariant conditions pass
 * 
 * @param self This security parameter
 */
bool BSL_SecParam_IsConsistent(const BSL_SecParam_t *self);

/** Indicates true when this parameter is NOT an implementation-specific security paramter.
 *
 * @todo Rename to avoid using negative logic and clarify.
 * @param param_id ID of the parameter
 * @returns True when this is NOT an internal parameter ID.
 */
bool BSL_SecParam_IsParamIDOutput(uint64_t param_id);

// bool BSL_SecParam_IsInit(const BSL_SecParam_t *self);

/** Initialize as a parameter containing a bytestring.
 *
 * @param self This Security Paramter
 * @param param_id ID of the parameter
 * @param value View of bytes, which get copied into this Security Parameter.
 * @returns Negative on an error.
 */
int BSL_SecParam_InitBytestr(BSL_SecParam_t *self, uint64_t param_id, BSL_Data_t value);

/** Initialize as a parameter containing an integer as a value.
 *
 * @param self This Security Paramter
 * @param param_id ID of the parameter
 * @param value View of bytes, which get copied into this Security Parameter.
 * @returns Negative on an error.
 */
int BSL_SecParam_InitInt64(BSL_SecParam_t *self, uint64_t param_id, uint64_t value);

/** Returns true when the value type is an integer.
 *
 * @param self This Security Parameter
 * @returns True when value type is integer.
 */
int BSL_SecParam_IsInt64(const BSL_SecParam_t *self);

/** Retrieve integer value of result when this result type is integer. WARNING: Always check using BSL_SecParam_IsInt64
 * first.
 *
 * @param self This Security Parameter
 * @returns Integer value of parameter if present, panics/aborts otherwise.
 */
uint64_t BSL_SecParam_GetAsUInt64(const BSL_SecParam_t *self);

/** Retrieve bytestring value of result when security parameter type is bytestring. WARNING: Always check type before
 * using.
 *
 * @todo Clarify whether result contains copy or view of content
 * @param self This Security Parameter
 * @param result Pointer to pre-allocated data into which the bytestring is copied.
 * @returns Negative on error.
 */
int BSL_SecParam_GetAsBytestr(const BSL_SecParam_t *self, BSL_Data_t *result);

// NOLINTBEGIN
/**
 * Defines a MLib basic list of Security Parameters.
 * @todo - Move to backend and replace with a forward declaration.
 */
LIST_DEF(BSL_SecParamList, BSL_SecParam_t, M_POD_OPLIST)
// NOLINTEND

/** Represents a Security Operation produced by a policy provider to inform the security context.
 *
 */
typedef struct BSL_SecOper_s
{
    /// @brief Security context ID
    uint64_t context_id;

    /// @brief Bundle's block ID over which the security operation is applied.
    uint64_t target_block_num;

    /// @brief Bundle's block ID which contains the security parameters and results for this operation.
    uint64_t sec_block_num;

    /// @brief Private enumeration indicating the role (e.g., acceptor vs verifier)
    BSL_SecRole_e      _role;
    BSL_SecBlockType_e _service_type;
    BSL_SecParamList_t _param_list;
} BSL_SecOper_t;

// NOLINTBEGIN
/// @todo - replace with forward declaration. Use new policy structure.
LIST_DEF(BSL_SecOperList, BSL_SecOper_t, M_POD_OPLIST)
// NOLINTEND

/** Populate a pre-allocated Security Operation with the given values.
 *
 * @param self Non-NULL pointer to this security operation.
 * @param context_id
 * @param target_block_num
 * @param sec_block_num
 * @param sec_type Member of BSL_SecBlock_Type_e enum indicating BIB or BCB
 * @param sec_role Member of BSL_SecRole_e enum indicating role.
 */
void BSL_SecOper_Init(BSL_SecOper_t *self, uint64_t context_id, uint64_t target_block_num, uint64_t sec_block_num,
                      BSL_SecBlockType_e sec_type, BSL_SecRole_e sec_role);

/** Empty and release any resources used internally by this structure.
 *
 * Certain backend implementations may create dynamic data structures that may need to be cleaned up,
 * so it is essential to call this under all circumstances.
 *
 * @param self Non-NULL pointer to this security operation
 */
void BSL_SecOper_Deinit(BSL_SecOper_t *self);

/** Returns true if internal consistency and sanity checks pass
 * 
 * @todo Formalize invariants
 * @param self This security operation
 * @return True if consistent, may assert false otherwise.
 */
bool BSL_SecOper_IsConsistent(const BSL_SecOper_t *self);

/** Returns a pointer to the Security Parameter at a given index in the list of all paramters.
 * @todo Clarify behavior if index is out of range.
 * @param self This security operation
 * @param index Index of security paramter list to retrieve from
 * @returns Pointer to security parameter type at given index.
 */
const BSL_SecParam_t *BSL_SecOper_GetParamAt(const BSL_SecOper_t *self, size_t index);

/** Get the count of parameters contained within this security operation.
 *
 * @param self This security operation.
 * @returns Count of security parameters.
 */
size_t BSL_SecOper_GetParamLen(const BSL_SecOper_t *self);

/** Add the given security parameter to this list of parameters.
 * @todo Clarify pointer/copy semantics.
 * @param self This security operation
 * @param param Security parameter to include.
 */
void BSL_SecOper_AppendParam(BSL_SecOper_t *self, const BSL_SecParam_t *param);

/** Return true if this security operation's role is SOURCE
 * @param self This Security Operation
 * @returns boolean
 */
bool BSL_SecOper_IsRoleSource(const BSL_SecOper_t *self);

/** Return true if this security operation's role is Verifier
 * @param self This Security Operation
 * @returns boolean
 */
bool BSL_SecOper_IsRoleVerifier(const BSL_SecOper_t *self);

/** Return true if this security operation's role is Acceptor
 * @param self This Security Operation
 * @returns boolean
 */
bool BSL_SecOper_IsRoleAccepter(const BSL_SecOper_t *self);

/** Return true if this security operation is BIB
 * @param self This security operation
 * @returns boolen
 */
bool BSL_SecOper_IsBIB(const BSL_SecOper_t *self);


#endif // BSL_BPSECTYPES_H_
