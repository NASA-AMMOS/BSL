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
 * Definition of the Abstract Security Block as defined in RFC 9172.
 * @ingroup frontend
 */
#ifndef BSL_ABSSECBLOCK_H
#define BSL_ABSSECBLOCK_H

#include "BPSecTypes.h"
#include "AdapterTypes.h"
#include "DataContainers.h"
#include "HostBPA.h"

/**
 * @struct uint64_list_t 
 * @brief Container for an MLib array of uint64_t
 * @cite lib:mlib.
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
LIST_DEF(uint64_list, uint64_t)
// NOLINTEND

/** Represents the Abstract Security Block as defined in RFC9172
 *
 */
typedef struct BSL_AbsSecBlock_s
{
    /// @brief List of target block ids.
    uint64_list_t targets;

    /// @brief Security context id
    uint64_t sec_context_id;

    /// @brief Source EID native representation, BSL host must take care of encoding/decoding.
    BSL_HostEID_t source_eid;

    /// @brief List of pointers to security paramters
    BSL_SecParamList_t params;

    /// @brief List of pointers to security results.
    BSL_SecResultList_t results;
} BSL_AbsSecBlock_t;

/** Populate a pre-allocated Absract Security Block
 *
 * @param self This ASB
 * @param sec_context_id Security Context ID
 * @param source_eid Source EID in format native to host BPA.
 */
void BSL_AbsSecBlock_Init(BSL_AbsSecBlock_t *self, uint64_t sec_context_id, BSL_HostEID_t source_eid);

/** Checks internal consistency and sanity of this structure.
 * 
 * @param self This ASB
 */
bool BSL_AbsSecBlock_IsConsistent(const BSL_AbsSecBlock_t *self);

/** Initialize a pre-allocated ASB with no contents.
 *
 * @param self This ASB
 */
void BSL_AbsSecBlock_InitEmpty(BSL_AbsSecBlock_t *self);

/** Deinitializes and clears this ASB, clearing and releasing any owned memory.
 * 
 * @param self This ASB
 */
void BSL_AbsSecBlock_Deinit(BSL_AbsSecBlock_t *self);

/** Prints to LOG INFO
 * 
 * @param self This ASB
 * @todo Refactor to dump this to a pre-allocated string.
 */
void BSL_AbsSecBlock_Print(const BSL_AbsSecBlock_t *self);

/** Determines whether this ASB has params and outcomes matching the given security outcome.
 * 
 * @param self This ASB
 * @param outcome Security outcome after execution from the security context.
 * @todo Better document, clarify invariants
 */
bool BSL_AbsSecBlock_IsResultEqual(const BSL_AbsSecBlock_t *self, const BSL_SecOutcome_t *outcome);

/** Returns true if this ASB contains nothing (i.e., no tarets, params and results)
 * 
 * @param self This ASB.
 */
bool BSL_AbsSecBlock_IsEmpty(const BSL_AbsSecBlock_t *self);

/** Returns true if a given ASB contains the given block number as a security target.
 * 
 * @param self This ASB.
 * @param target_block_num ID of a block, 0 indicates primary block
 */
bool BSL_AbsSecBlock_ContainsTarget(const BSL_AbsSecBlock_t *self, uint64_t target_block_num);


/** Adds a given block ID as a security target covered by this ASB
 * 
 * @param self This ASB.
 * @param target_block_id ID of a block, 0 indicates primary block as usual.
 */
void BSL_AbsSecBlock_AddTarget(BSL_AbsSecBlock_t *self, uint64_t target_block_id);

/** Add a security parameter to this security block (does NOT copy)
 *
 * @param self This security block
 * @param param Non-Null Security parameter pointer to add to list
 */
void BSL_AbsSecBlock_AddParam(BSL_AbsSecBlock_t *self, const BSL_SecParam_t *param);

/** Remove a given parameter as idenitifed by its parameter ID from this ASB
 *
 * @param self This ASB
 * @param param_id Security Parameter ID
 */
void BSL_AbsSecBlock_RemoveParam(BSL_AbsSecBlock_t *self, uint64_t param_id);

/** Add a security result to this security block (does NOT copy)
 *
 * @param self This security block
 * @param result Non-Null Security result pointer to add to list
 */
void BSL_AbsSecBlock_AddResult(BSL_AbsSecBlock_t *self, const BSL_SecResult_t *result);

/** Remove the target block ID from this ASB and all results.
 * 
 * @param self This ASB
 * @param target_block_id Target block number
 * @returns Number of results removed, zero indicates no change, negative on error.
 */
int BSL_AbsSecBlock_RemoveResult(BSL_AbsSecBlock_t *self, uint64_t target_block_id);

/** Remove security parameters and results found in `outcome` from this ASB
 *
 * @param self This ASB
 * @param outcome Security Operation outcome containing params and results
 * @return Negative on error, otherwise count of things removed.
 */
int BSL_AbsSecBlock_StripResults(BSL_AbsSecBlock_t *self, BSL_SecOutcome_t *outcome);

/** Encodes this ASB into a CBOR string into the space pre-allocated indicated by the argument.
 * 
 * @param self This ASB.
 * @param allocated_target A buffer with allocated space for the encoded CBOR
 * @return Integer contains number of bytes written to buffer, negative indicates error.
 * 
 */
int BSL_AbsSecBlock_EncodeToCBOR(const BSL_AbsSecBlock_t *self, BSL_Data_t allocated_target);

/** Decodes and populates this ASB from a CBOR string.
 * 
 * @param self This allocated, but uninitialized ASB to populate.
 * @param encoded_cbor A buffer containing a CBOR string representing the ASB
 * @return Negative on error
 */
int BSL_AbsSecBlock_DecodeFromCBOR(BSL_AbsSecBlock_t *self, BSL_Data_t encoded_cbor);


#endif /* BSL_ABSSECBLOCK_H */