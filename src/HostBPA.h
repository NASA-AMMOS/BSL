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
 * Abstract interface for BPA interaction from the BSL.
 * @ingroup frontend
 * 
 * @todo We need host interface functions for manipulating a Bundle, including
 *       functions like AddBlock, RemoveBlock, etc. Right now it just uses
 *       direct access using the Dynamic Backend.
 */
#ifndef BSL_HOST_BPA_H
#define BSL_HOST_BPA_H


#include <m-string.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque pointer to BPA-specific Endpoint ID storage.
 * Ownership of the object is kept by the BPA, and these are only references.
 */
typedef struct BSL_HostEID_s
{
    /// Opaque pointer for BPA backend to use
    void *handle;
} BSL_HostEID_t;

/** Static initializer for an invalid ::BSL_HostEID_t.
 * Even after this, BSL_HostEID_Init() must be used to get into a valid state.
 */
#define BSL_HOSTEID_INIT_INVALID { .handle = NULL }

/** Initialize an abstract EID.
 *
 * @param[out] eid The object to initialize.
 * @return Zero if successful.
 */
int BSL_HostEID_Init(BSL_HostEID_t *eid);

/** De-initialize an abstract EID.
 *
 * @param[in,out] eid The object to de-initialize.
 */
void BSL_HostEID_Deinit(BSL_HostEID_t *eid);

/** Get the local EID used when this node is a security source.
 *
 * @param[out] eid The EID to write into.
 * This must already be initialized.
 * @return Zero if successful.
 * @sa BSL_ROLE_SOURCE
 */
int BSL_Host_GetSecSrcEID(BSL_HostEID_t *eid);

/** Decode an EID from its text form.
 *
 * @param[out] eid The EID to write into.
 * This must already be initialized.
 * @param[in] text The text to read from, which must be non-null.
 * @return Zero if successful.
 */
int BSL_HostEID_DecodeFromText(BSL_HostEID_t *eid, const char *text);

/** Encode an EID to its text form.
 *
 * @param[out] out The encoded result to append.
 * This must already be initialized.
 * @param[in] eid The EID encode from.
 * This must already be initialized.
 * @return Zero if successful.
 */
int BSL_HostEID_EncodeToText(string_t out, const BSL_HostEID_t *eid);

/** Load an EID from CBOR
 * 
 * @param[in,out] eid This eid
 * @param[in] CBOR decoder context
 * @return 0 on success
 */
int BSL_HostEID_DecodeFromCBOR(BSL_HostEID_t *eid, void *decoder);

/** Opaque pointer to BPA-specific Endpoint ID Pattern storage.
 * Ownership of the object is kept by the BPA, and these are only references.
 */
typedef struct BSL_HostEIDPattern_s
{
    /// Opaque pointer for BPA backend to use
    void *handle;
} BSL_HostEIDPattern_t;

/** Static initializer for an invalid ::BSL_HostEIDPattern_t.
 * Even after this, BSL_HostEIDPattern_Init() must be used to get into a valid state.
 */
#define BSL_HOSTEID_INIT_INVALID { .handle = NULL }

/** Initialize an abstract EID Pattern.
 *
 * @param[out] pat The object to initialize.
 * @return Zero if successful.
 */
int BSL_HostEIDPattern_Init(BSL_HostEIDPattern_t *pat);

/** De-initialize an abstract EID Pattern.
 *
 * @param[in,out] pat The object to de-initialize.
 */
void BSL_HostEIDPattern_Deinit(BSL_HostEIDPattern_t *pat);

/**
 * Encode a EID into a CBOR sequence
 */
int BSL_HostEID_EncodeToCBOR(const BSL_HostEID_t *eid, void *user_data);

/** Decode an EID Pattern from its text form.
 *
 * @param[out] pat The pattern to write into.
 * This must already be initialized.
 * @param[in] text The text to read from, which must be non-null.
 * @return Zero if successful.
 */
int BSL_HostEIDPattern_DecodeFromText(BSL_HostEIDPattern_t *pat, const char *text);

/** Determine if an EID Pattern matches a specific EID.
 *
 * @param[in] pat The pattern to compare.
 * @param[in] eid The EID to compare.
 * @return True if the EID is a match to the pattern.
 */
bool BSL_HostEIDPattern_IsMatch(const BSL_HostEIDPattern_t *pat, const BSL_HostEID_t *eid);

/** Opaque pointer to BPA-specific label storage.
 * Ownership of the object is kept by the BPA, and these are only references.
 */
typedef struct BSL_HostLabel_s
{
    /// Opaque pointer for BPA backend to use
    void *handle;
} BSL_HostLabel_t;

/** Static initializer for an invalid ::BSL_HostLabel_t.
 * Even after this, BSL_HostLabel_Init() must be used to get into a valid state.
 */
#define BSL_HOSTLABEL_INIT_INVALID { .handle = NULL }

/** Initialize an abstract label.
 *
 * @param[out] label The object to initialize.
 * @return Zero if successful.
 */
int BSL_HostLabel_Init(BSL_HostLabel_t *label);

/** De-initialize an abstract label.
 *
 * @param[in,out] label The object to de-initialize.
 */
void BSL_HostLabel_Deinit(BSL_HostLabel_t *label);

/** Decode a label from its text form.
 *
 * @param[out] label The object to write into.
 * This must already be initialized.
 * @param[in] text The text to read from, which must be non-null.
 * @return Zero if successful.
 */
int BSL_HostLabel_DecodeFromText(BSL_HostLabel_t *label, const char *text);

/** Encode a label to its text form.
 *
 * @param[out] out The encoded result to append.
 * This must already be initialized.
 * @param[in] label The object encode from.
 * This must already be initialized.
 * @return Zero if successful.
 */
int BSL_HostLabel_EncodeToText(string_t out, const BSL_HostLabel_t *label);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_HOST_BPA_H
