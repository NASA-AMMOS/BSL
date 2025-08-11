/*
 * Copyright (c) 2025 The Johns Hopkins University Applied Physics
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
 * Single entry-point include file for all of the "Public" BPSec Lib (BSL) frontend API.
 * @ingroup frontend
 * @details
 * This contains the interface for the BPA.
 *
 * @author Bill.Van.Besien@jhuapl.edu
 */
#ifndef BSL_BPSECLIB_PUBLIC_H_
#define BSL_BPSECLIB_PUBLIC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// This annotation on a function requires the caller to capture and inspect the return value.
#if defined(__GNUC__) || defined(__clang__)
#define BSL_REQUIRE_CHECK __attribute__((warn_unused_result))
#else
#define BSL_REQUIRE_CHECK
#endif

/// Forward declaration for BSL library context.
typedef struct BSL_LibCtx_s BSL_LibCtx_t;

/// @brief Forward declaration of ::BSL_SecurityResponseSet_s, which contains information for BSL and the host BPA to
/// process the Bundle.
typedef struct BSL_SecurityResponseSet_s BSL_SecurityResponseSet_t;

/// @brief Forward declaration of ::BSL_SecurityActionSet_s, which contains information for BSL to process the Bundle.
typedef struct BSL_SecurityActionSet_s BSL_SecurityActionSet_t;

/// @brief Forward-declaration for structure containing callbacks to a security context.
typedef struct BSL_SecCtxDesc_s BSL_SecCtxDesc_t;

/// @brief Forward-declaration for structure containing callbacks to  provider.
typedef struct BSL_PolicyDesc_s BSL_PolicyDesc_t;

#define BSL_DEFAULT_STRLEN (128)
typedef char BSL_StaticString_t[BSL_DEFAULT_STRLEN];

/** @brief Indicates where in the lifecycle of the BPA the bundle is querying for security policy.
 *
 * @note The numeric values of the enum are arbitrary. We avoid using 0 as defaults.
 */
typedef enum
{
    /// @brief Bundle source at creation
    BSL_POLICYLOCATION_APPIN = 101,
    /// @brief Bundle destination at delivery
    BSL_POLICYLOCATION_APPOUT,
    /// @brief Bundle ingress from CLA
    BSL_POLICYLOCATION_CLIN,
    /// @brief Bundle egress to CLA
    BSL_POLICYLOCATION_CLOUT
} BSL_PolicyLocation_e;

/**
 * @brief Indicates the conclusion state of a security operation
 */
typedef enum
{
    /// @brief Security operation is still pending action
    BSL_SECOP_CONCLUSION_PENDING = 1,
    /// @brief Security operation has concluded and succeeded
    BSL_SECOP_CONCLUSION_SUCCESS,
    /// @brief Security operation is invalid
    BSL_SECOP_CONCLUSION_INVALID,
    /// @brief Security operation has concluded and failed
    BSL_SECOP_CONCLUSION_FAILURE
} BSL_SecOper_ConclusionState_e;

/** Block CRC types.
 * Defined in Section 4.2.1 of RFC 9171 @cite rfc9171.
 */
typedef enum
{
    /// @brief No CRC value
    BSL_BUNDLECRCTYPE_NONE = 0,
    /// @brief CRC-16
    BSL_BUNDLECRCTYPE_16 = 1,
    /// @brief CRC-32C
    BSL_BUNDLECRCTYPE_32 = 2,
} BSL_BundleCRCType_e;

/** @brief Opaque pointer to BPA-specific Endpoint ID storage.
 *
 * Ownership of the object is kept by the BPA, and these are only references.
 */
typedef struct BSL_HostEID_s
{
    void *handle; ///< Opaque pointer for BPA backend to use
} BSL_HostEID_t;

/** @brief Reference to a EID pattern owned and stored in the BPA.
 *
 */
typedef struct BSL_HostEIDPattern_s
{
    void *handle; ///< Opaque pointer for BPA backend to use
} BSL_HostEIDPattern_t;

/** @brief Reference to a Bundle owned and stored in the host BPA
 *
 * @note The BSL internally never attempts to parse the opaque pointer contained here.
 */
typedef struct BSL_BundleRef_s
{
    void *data; ///< Opaque pointer, not used by the BSL.
} BSL_BundleRef_t;

/** @brief Contains Bundle Primary Block fields and metadata.
 *
 *  @note This contains a *snapshot* of the fields at the time it was queried. It is not a pointer.
 */
typedef struct BSL_PrimaryBlock_s
{
    uint64_t      field_version;              ///< CBOR-decoded field of Primary Block BP version
    uint64_t      field_flags;                ///< CBOR-decoded field of bundle processing control flags
    uint64_t      field_crc_type;             ///< CBOR-decoded field of Primary Block CRC type
    BSL_HostEID_t field_dest_eid;             ///< Destination in host BPA's internal representation of an EID
    BSL_HostEID_t field_src_node_id;          ///< Source in host BPA's internal representation of an EID
    BSL_HostEID_t field_report_to_eid;        ///< Report-to EID in host BPA's internal representation of an EID.
    uint64_t      field_bundle_creation_time; ///< CBOR-decoded bundle creation time
    uint64_t      field_seq_num;              ///< CBOR-decoded sequence number
    uint64_t      field_lifetime;             ///< CBOR-decoded lifetime
    uint64_t      field_frag_offset;          ///< CBOR-decoded fragment offset (warning, may not be implemented yet).
    uint64_t      field_adu_length;           ///< CBOR-decoded field of ADU length
    size_t        block_count; ///< Helpful count of total canonical blocks in bundle, not a field of the header.
    uint8_t      *cbor;
    size_t        cbor_len;
} BSL_PrimaryBlock_t;

/** @brief Structure containing parsed Canonical Block fields.
 *
 *  @note This contains a *snapshot* of the fields at the time it was queried. It is not a pointer.
 */
typedef struct BSL_CanonicalBlock_s
{
    uint64_t block_num; ///< CBOR-decoded block number (should always be > 0)
    uint64_t type_code; ///< CBOR-decoded block type code (should be > 0)
    uint64_t flags;     ///< CBOR-decoded flags field
    uint64_t crc;       ///< CBOR-decoded block CRC
    void    *btsd;      ///< Pointer to BTSD owned by the host BPA
    size_t   btsd_len;  ///< Length in bytes of the BTSD pointer.
} BSL_CanonicalBlock_t;

/** Dynamic BPA descriptor.
 */
typedef struct
{
    /// User data pointer for callbacks
    void *user_data;

    /// @brief Host BPA function to get its current EID
    int (*get_host_eid_fn)(const void *user_data, BSL_HostEID_t *result);

    /// @brief Host BPA function to initialize/allocate an EID type.
    int (*eid_init)(void *user_data, BSL_HostEID_t *result);

    /// @brief Host BPA function to deinit/free an EID type.
    void (*eid_deinit)(void *user_data, BSL_HostEID_t *eid);

    /// @brief Host BPA function to populate a Primary Block struct.
    int (*bundle_metadata_fn)(const BSL_BundleRef_t *bundle_ref, BSL_PrimaryBlock_t *result_primary_block);

    /// @brief Host BPA function to populate a pre-allocated array with canonical block IDs
    int (*bundle_get_block_ids)(const BSL_BundleRef_t *bundle_ref, size_t array_count,
                                uint64_t array_block_ids[array_count], size_t *result_count);

    /// @brief Host BPA function to populate a Canonical Block struct for a given block number.
    int (*block_metadata_fn)(const BSL_BundleRef_t *bundle_ref, uint64_t block_num, BSL_CanonicalBlock_t *result_block);

    /// @brief Host BPA function to create a new canonical block with the given type, returning result in the output
    /// pointer.
    int (*block_create_fn)(BSL_BundleRef_t *bundle_ref, uint64_t block_type_code, uint64_t *result_block_num);

    /// @brief Host BPA function to remove a given canonical block from the bundle
    int (*block_remove_fn)(BSL_BundleRef_t *bundle_ref, uint64_t block_num);

    /// @brief Host BPA function to reallocate a canonical block's BTSD, keeping existing data in-place.
    int (*block_realloc_btsd_fn)(BSL_BundleRef_t *bundle_ref, uint64_t block_num, size_t bytesize);

    /// @brief Host BPA function to delete Bundle
    int (*bundle_delete_fn)(BSL_BundleRef_t *bundle_ref);

    /// @brief Host BPA function to encode an EID to CBOR.
    int (*eid_to_cbor)(void *encoder, const BSL_HostEID_t *eid);

    /// @brief Host BPA function to decode an EID from a CBOR context
    int (*eid_from_cbor)(void *encoder, BSL_HostEID_t *eid);

    /// @brief Host BPA function to parse an EID from a C-string
    int (*eid_from_text)(BSL_HostEID_t *eid, const char *text, void *user_data);

    /// @brief Host BPA function to initialize an EID pattern type
    int (*eidpat_init)(BSL_HostEIDPattern_t *pat, void *user_data);

    /// @brief Host BPA function to deinit an EID pattern type.
    void (*eidpat_deinit)(BSL_HostEIDPattern_t *pat, void *user_data);

    /// @brief Host BPA function to parse an EID pattern from a C-string
    int (*eidpat_from_text)(BSL_HostEIDPattern_t *pat, const char *text, void *user_data);

    /// @brief Host BPA function that returns true if the given EID matched an EID pattern.
    bool (*eidpat_match)(const BSL_HostEIDPattern_t *pat, const BSL_HostEID_t *eid, void *user_data);
} BSL_HostDescriptors_t;

/** Set the BPA descriptor (callbacks) for this process.
 *
 * @warning This function is not thread safe and should be set before any
 * ::BSL_LibCtx_t is initialized or other BSL interfaces used.
 *
 * @param desc The descriptor to use for future BPA functions.
 * @return Zero if successful, negative on error.
 */
int BSL_HostDescriptors_Set(BSL_HostDescriptors_t desc);

/** Copy the BPA descriptor for this process.
 * @note This function is not thread safe.
 *
 * @param[out] desc The descriptor to copy into.
 */
void BSL_HostDescriptors_Get(BSL_HostDescriptors_t *desc);

/** @brief Initialize the BPSecLib (BSL) library context.
 *
 * @note This only needs to be done once per lifetime of the BSL.
 *
 * @param[in,out] bsl Pointer to allocated space for the library context.
 * @returns 0 on success, negative on error.
 */
BSL_REQUIRE_CHECK
int BSL_API_InitLib(BSL_LibCtx_t *bsl);

/** @brief Deinitialize and release any resources held by the BSL.
 * @note This only needs to be run once per lifetime of the BSL.
 *
 * @param[in,out] bsl Pointer to library context
 * @returns 0 on success, negative on error.
 */
BSL_REQUIRE_CHECK
int BSL_API_DeinitLib(BSL_LibCtx_t *bsl);

/** @brief Register a security context module with the BSL.
 *
 * @note The Security Context interface is defined by the security context descriptor.
 * @param[in,out] lib           Pointer to BSL context.
 * @param[in] sec_ctx_id        Security context ID
 * @param[in] desc              Descriptor struct containing callbacks.
 */
BSL_REQUIRE_CHECK
int BSL_API_RegisterSecurityContext(BSL_LibCtx_t *lib, uint64_t sec_ctx_id, BSL_SecCtxDesc_t desc);

/** @brief Register a Policy Provider module with the BSL.
 * @note The Policy Provider interface is defined by the policy provider descriptor.
 *
 * @param[in,out] lib   Pointer to BSL context.
 * @param[in]     desc  Policy Provider callbacks.
 */
BSL_REQUIRE_CHECK
int BSL_API_RegisterPolicyProvider(BSL_LibCtx_t *lib, BSL_PolicyDesc_t desc);

/** @brief Query BSL to populate a `BSL_SecurityActionSet_t` containing security processing instructions.
 *
 * @details
 * This executes a chain of events in the BSL. First by querying the policy provider, then checking with the security
 * context for viability. It returns 0 and a populated `BSL_SecurityActionSet_` with the security operations and their
 * parameters, if successful.
 *
 * @note A BSL guideline is that caller's generally allocate the memory for callee's. In this case, the BPA must create
 * space for the output action set using `_Sizeof` functions for the respective structures.
 *
 * @param[in]       bsl               Pointer to BSL context.
 * @param[in,out]   output_action_set Pointer to pre-allocated structure into which security operations will be
 * populated.
 * @param[in]       bundle            Reference to BPA-owned bundle.
 * @param[in]       location          "Location" within the BPA (e.g,. "At app egress")
 * @returns 0 on success, negative on error. On zero, `output_action_set` will be populated.
 */
BSL_REQUIRE_CHECK
int BSL_API_QuerySecurity(const BSL_LibCtx_t *bsl, BSL_SecurityActionSet_t *output_action_set,
                          const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location);

/** @brief Performs the given security operations on a Bundle, modifying or even dropping it entirely.
 *
 * @param[in]     bsl             Pointer to BSL context structure.
 * @param[out]    response_output Pointer to host-allocated output structure.
 * @param[in,out] bundle          Reference to host-owned Bundle, which may be modified or dropped by the BSL.
 * @param[in]     policy_actions  Pointer to policy actions, which was populated using the `QuerySecurity` function.
 */
BSL_REQUIRE_CHECK
int BSL_API_ApplySecurity(const BSL_LibCtx_t *bsl, BSL_SecurityResponseSet_t *response_output, BSL_BundleRef_t *bundle,
                          const BSL_SecurityActionSet_t *policy_actions);

#endif /* BSL_BPSECLIB_PUBLIC_H_ */
