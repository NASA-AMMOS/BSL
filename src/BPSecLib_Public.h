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

#include "BSLConfig.h"
#include "Data.h"

#ifdef __cplusplus
extern "C" {
#endif

/// This annotation on a function requires the caller to capture and inspect the return value.
#if defined(__GNUC__) || defined(__clang__)
#define BSL_REQUIRE_CHECK __attribute__((warn_unused_result))
#else
#define BSL_REQUIRE_CHECK
#endif

/// Forward declaration for BSL library context.
typedef struct BSL_LibCtx_s BSL_LibCtx_t;

/**
 * Return size of library context
 */
size_t BSL_LibCtx_Sizeof(void);

/// @brief Forward declaration of ::BSL_SecurityResponseSet_s, which contains information for BSL and the host BPA to
/// process the Bundle.
typedef struct BSL_SecurityResponseSet_s BSL_SecurityResponseSet_t;

/// @brief Forward declaration of ::BSL_SecurityActionSet_s, which contains actions for BSL to process the Bundle.
typedef struct BSL_SecurityActionSet_s BSL_SecurityActionSet_t;

/// @brief Forward declaration of ::BSL_SecurityAction_s, which contains security operations for BSL to process the
/// Bundle.
typedef struct BSL_SecurityAction_s BSL_SecurityAction_t;

/// @brief Forward-declaration for structure containing callbacks to a security context.
typedef struct BSL_SecCtxDesc_s BSL_SecCtxDesc_t;

/// @brief Forward-declaration for structure containing callbacks to  provider.
typedef struct BSL_PolicyDesc_s BSL_PolicyDesc_t;

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

#define BSL_TLM_COUNTERS_ZERO \
    (BSL_TlmCounters_t)       \
    {                         \
        0                     \
    }

/** @brief Defined indices for the counter structure to hold telemetry and counts
 *
 * @note If more telemetry is added, the array in ::BSL_TlmCounters_t must be updated.
 */
typedef enum
{
    BSL_TLM_BUNDLE_INSPECTED_COUNT = 0,
    BSL_TLM_BUNDLE_INSPECTED_BYTES,
    BSL_TLM_ASB_DECODE_COUNT,
    BSL_TLM_ASB_DECODE_BYTES,
    BSL_TLM_ASB_ENCODE_COUNT,
    BSL_TLM_ASB_ENCODE_BYTES,
    BSL_TLM_SECOP_SOURCE_COUNT,
    BSL_TLM_SECOP_VERIFIER_COUNT,
    BSL_TLM_SECOP_ACCEPTOR_COUNT,
    BSL_TLM_SECOP_FAIL_COUNT,
    BSL_TLM_TOTAL_COUNT
} BSL_TlmCounterIndex_e;

/** @brief The telemetry counter structure to store the enumerations of telemetry.
 *
 * This structure is automatically created in the BSL context
 */
typedef struct BSL_TlmCounters_s
{
    uint64_t counters[BSL_TLM_TOTAL_COUNT + 1];
} BSL_TlmCounters_t;

/** @brief Retrieve copy of the telemetry counters to accumulate in BPA.
 *
 * @param[in] lib           Pointer to BSL context.
 * @param[out] sec_ctx_id       Pointer to the output telemetry structure
 * @returns 0 on success, negative on error.
 */
int BSL_LibCtx_AccumulateTlmCounters(const BSL_LibCtx_t *lib, BSL_TlmCounters_t *tlm);

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
 * @note The BSL internally never attempts to dereference the opaque pointer contained here.
 */
typedef struct BSL_BundleRef_s
{
    void *data; ///< Opaque pointer, not used by the BSL.
} BSL_BundleRef_t;

typedef enum
{
    BSL_REASONCODE_NO_ADDITIONAL_INFO   = 0,
    BSL_REASONCODE_DEPLETED_STORAGE     = 4,
    BSL_REASONCODE_BLOCK_UNINTELLIGIBLE = 8,
    BSL_REASONCODE_MISSING_SECOP        = 12,
    BSL_REASONCODE_UNKNOWN_SECOP        = 13,
    BSL_REASONCODE_UNEXPECTED_SECOP     = 14,
    BSL_REASONCODE_FAILED_SECOP         = 15,
    BSL_REASONCODE_CONFLICTING_SECOP    = 16
} BSL_ReasonCode_e;

/** @brief Contains Bundle Primary Block fields and metadata.
 *
 *  @note This contains a *snapshot* of the fields at the time it was queried. It is not a pointer.
 *
 * Instances are initialized as part of BSL_BundleCtx_GetBundleMetadata().
 * Instances are de-initialized with BSL_PrimaryBlock_deinit().
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

    /// Helpful count of total canonical blocks in bundle, not a field of the header.
    size_t block_count;
    /** Array of size #block_count containing canonical block numbers in
     * the same order in which they appear in the bundle.
     */
    uint64_t *block_numbers;

    /** The encoded form of the primary block as contiguous data.
     */
    BSL_Data_t encoded;
} BSL_PrimaryBlock_t;

/** Deinitialize the use of a primary block metadata.
 *
 * @param[in,out] obj The instance to deinit.
 */
void BSL_PrimaryBlock_deinit(BSL_PrimaryBlock_t *obj);

/** @brief Structure containing parsed Canonical Block fields.
 *
 *  @note This contains a *snapshot* of the fields at the time it was queried. It is not a pointer.
 */
typedef struct BSL_CanonicalBlock_s
{
    uint64_t block_num; ///< CBOR-decoded block number (should always be > 0)
    uint64_t type_code; ///< CBOR-decoded block type code (should be > 0)
    uint64_t flags;     ///< CBOR-decoded flags field
    uint64_t crc_type;  ///< CBOR-decoded block CRC Type
    size_t   btsd_len;  ///< Length in bytes of the BTSD accessible through sequential APIs
} BSL_CanonicalBlock_t;

/** Dynamic BPA descriptor.
 */
typedef struct
{
    /// User data pointer for callbacks
    void *user_data;

    /// @brief Host BPA function to get its security source EID
    int (*get_sec_src_eid_fn)(void *user_data, BSL_HostEID_t *result);

    /// @brief Host BPA function to initialize/allocate an EID type.
    int (*eid_init)(void *user_data, BSL_HostEID_t *result);

    /// @brief Host BPA function to deinit/free an EID type.
    void (*eid_deinit)(void *user_data, BSL_HostEID_t *eid);

    /// @brief Host BPA function to populate a Primary Block struct.
    int (*bundle_metadata_fn)(const BSL_BundleRef_t *bundle_ref, BSL_PrimaryBlock_t *result_primary_block);

    /// @brief Host BPA function to populate a Canonical Block struct for a given block number.
    int (*block_metadata_fn)(const BSL_BundleRef_t *bundle_ref, uint64_t block_num, BSL_CanonicalBlock_t *result_block);

    /// @brief Host BPA function to create a new canonical block with the given type, returning result in the output
    /// pointer.
    int (*block_create_fn)(BSL_BundleRef_t *bundle_ref, uint64_t block_type_code, uint64_t *result_block_num);

    /// @brief Host BPA function to remove a given canonical block from the bundle
    int (*block_remove_fn)(BSL_BundleRef_t *bundle_ref, uint64_t block_num);

    /// @brief Host BPA function to reallocate a canonical block's BTSD, keeping existing data in-place.
    /// @deprecated use sequential writer to do this
    int (*block_realloc_btsd_fn)(BSL_BundleRef_t *bundle_ref, uint64_t block_num, size_t bytesize);

    /** Host BPA function do create a new sequential reader on a single block-type-specific data.
     *
     * @param[in] bundle_ref The bundle to read data from.
     * @param block_num The specific block number to read BTSD from.
     * @return A pointer to a reader struct or NULL if the reader cannot
     * be configured for any reason.
     */
    struct BSL_SeqReader_s *(*block_read_btsd_fn)(const BSL_BundleRef_t *bundle_ref, uint64_t block_num);

    /** Host BPA function do create a new sequential writer on a single block-type-specific data.
     * The writer will call BSL_SeqWriter_Destroy() when it is finished.
     *
     * @note The BPA must double-buffer to allow a reader and writer on the same block.
     *
     * @param[in] bundle_ref The bundle to read data from.
     * @param block_num The specific block number to write BTSD into.
     * @param total_size A hint as to the total size that will be written.
     * @return A pointer to a reader struct or NULL if the reader cannot
     * be configured for any reason.
     */
    struct BSL_SeqWriter_s *(*block_write_btsd_fn)(BSL_BundleRef_t *bundle_ref, uint64_t block_num, size_t total_size);

    /// @brief Host BPA function to delete Bundle with a reason code
    int (*bundle_delete_fn)(BSL_BundleRef_t *bundle_ref, BSL_ReasonCode_e reason);

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
 * @warning This function is not thread safe and should be used before any
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

/** Reset the host descriptors to their default, unusable state.
 *
 * @warning This function is not thread safe and should be used after any
 * ::BSL_LibCtx_t is deinitialized.
 */
void BSL_HostDescriptors_Clear(void);

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
int BSL_API_RegisterPolicyProvider(BSL_LibCtx_t *lib, uint64_t pp_id, BSL_PolicyDesc_t desc);

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

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_BPSECLIB_PUBLIC_H_ */
