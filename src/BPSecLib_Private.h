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
 * Single entry-point include file for all of the BPSec Lib (BSL) frontend API.
 * @ingroup frontend
 *
 * @details
 * This file is for backend and BSL-adjacent modules (the Policy Provider, Security Context, and Test Harness) to have
 * more reach into the BSL, without requring any of them to have specific dependencies on the other. The Host BPA should
 * only need the purely public header file.
 *
 * @author Bill.Van.Besien@jhuapl.edu
 */

#ifndef BSL_BPSECLIB_PRIVATE_H_
#define BSL_BPSECLIB_PRIVATE_H_

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <qcbor/UsefulBuf.h>

#include "BPSecLib_Public.h"

/** @brief Catalog of error code
 *
 * @note BSL error codes are negative, such that a caller can check `if (BSL_MyFunc(...) < 0)` for errors.
 */
typedef enum
{
    BSL_SUCCESS                       = 0,   ///< Placeholder for non-error code
    BSL_ERR_FAILURE                   = -1,  ///< Uncategorized failed (prefer to avoid)
    BSL_ERR_ARG_NULL                  = -2,  ///< Function pointer argument is NULL
    BSL_ERR_ARG_INVALID               = -3,  ///< Function argument does not satisfy a given predicate.
    BSL_ERR_PROPERTY_CHECK_FAILED     = -4,  ///< The BSL of a structure within it is not in a valid state.
    BSL_ERR_INSUFFICIENT_SPACE        = -5,  ///< Insufficient space to complete.
    BSL_ERR_NOT_IMPLEMENTED           = -6,  ///< Requested functionality not yet implemented.
    BSL_ERR_ENCODING                  = -7,  ///< CBOR encoding failure
    BSL_ERR_DECODING                  = -8,  ///< CBOR decoding failure.
    BSL_ERR_NOT_FOUND                 = -9,  ///< Requested value not found for key
    BSL_ERR_BUNDLE_OPERATION_FAILED   = -10, ///< Bundle manipulation failed (add/remove or change BTSD)
    BSL_ERR_SECURITY_OPERATION_FAILED = -11, ///< Security operation failed (e.g., BIB did not have enough parameters)
    BSL_ERR_HOST_CALLBACK_FAILED      = -12, ///< Callback to the host BPA returned a non-zero code.

    /// Policy Errors start at 100
    BSL_ERR_POLICY_FAILED = -100, ///< General error code for errors arising from a Policy Provider

    /// Security Context errors start at 200
    BSL_ERR_SECURITY_CONTEXT_FAILED       = -200, ///< General error code for errors arising from a Security Context.
    BSL_ERR_SECURITY_CONTEXT_PARTIAL_FAIL = -201, ///< General code where at least some security operations failed.
    BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED = -202 ///< Indicates an HMAC signature did not match
} BSL_ErrCodes_e;

/** Mark an unused parameter Within a function definition.
 * This avoids compiler warnings when parameters need to be present to satisfy
 * an interface but are otherwise unused.
 *
 * For example, this second parameter is marked unused:
 * @code{.c}
 * void myfunc(int param, int unused _U_)
 * @endcode
 */
#if defined(__GNUC__) || defined(__clang__)
#define _U_ __attribute__((unused)) // NOLINT
#elif defined(_MSC_VER)
#define _U_ __pragma(warning(suppress : 4100 4189))
#else
#define _U_
#endif

/** @def UNLIKELY(expr)
 * Hint to the compiler that the expression is expected to evaluate to false
 * and the associated branch is unlikely.
 * @param expr The expression to evaluate.
 * @return The boolean evaluation of the expression.
 */
/** @def LIKELY(expr)
 * Hint to the compiler that the expression is expected to evaluate to true
 * and the associated branch is likely.
 * @param expr The expression to evaluate.
 * @return The boolean evaluation of the expression.
 */
#ifndef UNLIKELY
#if defined(__GNUC__)
#define UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#define LIKELY(expr)   __builtin_expect(!!(expr), 1)
#else
#define UNLIKELY(expr) (expr)
#define LIKELY(expr)   (expr)
#endif
#endif /* UNLIKELY */

// Note, the following CHK macros are deprecated.
/** Check a condition and if not met return a specific value.
 *
 * @param cond The conditition to check.
 * @param val The return value if the check fails.
 * @deprecated
 */
#define CHKRET(cond, val) \
    if (!LIKELY(cond))    \
    {                     \
        return val;       \
    }
/// Return from void functions if condition fails.
#define CHKVOID(cond) CHKRET(cond, )
/// Return a null pointer if condition fails.
#define CHKNULL(cond) CHKRET(cond, NULL)
/// Return false if condition fails.
#define CHKFALSE(cond) CHKRET(cond, false)
/// Return the error value 1 if condition fails.
#define CHKERR1(cond) CHKRET(cond, 1)
/** Check a value for non-zero and return that value.
 * @warning The parameter is evaluated twice so should be a simple variable.
 *
 * @param value The value to check and conditionally return.
 */
#define CHKERRVAL(value) CHKRET(!(value), (value))

/** @brief Codes indicating the fate of a block if a security operation over it fails
 *
 */
typedef enum
{
    BSL_POLICYACTION_UNDEFINED = 0, ///< Placeholder for zero - should never occur.
    BSL_POLICYACTION_NOTHING,       ///< Do nothing, keep the block even if it fails.
    BSL_POLICYACTION_DROP_BLOCK,    ///< Drop on the target block.
    BSL_POLICYACTION_DROP_BUNDLE    ///< Drop the entire bundle.
} BSL_PolicyAction_e;

/**
 * Helper function to print the ASCII encoding of a given bytestream to a given target buffer.
 *
 * @todo - Can be moved to backend.
 *
 * @param dstbuf Pointer to a buffer where the c string should go.
 * @param dstlen The length in bytes of dstbuf
 * @param srcbuf Pointer to the buffer containing the bytestream to be printed.
 * @param srclen The length in bytes of srcbuf.
 * @return The number of bytes written to dstbuf. It will not exceed dstlen.
 */
uint8_t *BSL_Log_DumpAsHexString(uint8_t *dstbuf, size_t dstlen, const uint8_t *srcbuf, size_t srclen);

/** Opens the event log.
 * @note This should be called once per process, not thread or library instance.
 * At the end of the process there should be a call to BSL_closelog()
 *
 * This is a mimic to POSIX openlog()
 */
void BSL_openlog(void);

/** Closes the event log.
 * This is a mimic to POSIX closelog()
 * @sa BSL_openlog
 */
void BSL_closelog(void);

/** Log an event.
 *
 * @param severity The severity from a subset of the POSIX syslog values.
 * @param[in] filename The originating file name, which may include directory parts.
 * @param[in] lineno The originating file line number.
 * @param[in] funcname The originating function name.
 * @param[in] format The log message format string.
 * @param ... Values for the format string.
 */
void BSL_LogEvent(int severity, const char *filename, int lineno, const char *funcname, const char *format, ...);

// NOLINTBEGIN(misc-include-cleaner)
/** Perform LOG_CRIT level logging with auto-filled parameters.
 * The arguments to this macro are passed to BSL_LogEvent() as the @c format and
 * its parameter values.
 */
#define BSL_LOG_CRIT(...) BSL_LogEvent(LOG_CRIT, __FILE__, __LINE__, __func__, __VA_ARGS__)
/// @overload
#define BSL_LOG_ERR(...) BSL_LogEvent(LOG_ERR, __FILE__, __LINE__, __func__, __VA_ARGS__)
/// @overload
#define BSL_LOG_WARNING(...) BSL_LogEvent(LOG_WARNING, __FILE__, __LINE__, __func__, __VA_ARGS__)
/// @overload
#define BSL_LOG_INFO(...) BSL_LogEvent(LOG_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__)
/// @overload
#define BSL_LOG_DEBUG(...) BSL_LogEvent(LOG_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)
// NOLINTEND(misc-include-cleaner)

/** @brief Helpful macros for expressing invariants, pre/post conditions, and arg validation
 *
 */
#define CHK_TEMPL(expr, msg, return_code)                                      \
    do                                                                         \
    {                                                                          \
        if (!(expr))                                                           \
        {                                                                      \
            BSL_LOG_ERR("" msg " (" #expr ") ... [errcode=" #return_code "]"); \
            assert(!(expr));                                                   \
            return return_code;                                                \
        }                                                                      \
    }                                                                          \
    while (0)

#define CHK_AS_BOOL(expr) CHK_TEMPL(expr, "Failed Property Check: Failed to satisfy", BSL_ERR_ARG_INVALID)

#define CHK_ARG_EXPR(expr) \
    CHK_TEMPL(expr, "Illegal Argument: Argument expression check failed to satisfy", BSL_ERR_ARG_INVALID)

#define CHK_ARG_NONNULL(var) \
    CHK_TEMPL((var) != NULL, "Illegal Argument: Argument null check failed to satisfy", BSL_ERR_ARG_NULL)

#define CHK_PRECONDITION(expr) CHK_TEMPL(expr, "Precondition Failed: Did not satisfy", BSL_ERR_FAILURE);

#define CHK_PROPERTY(expr) CHK_TEMPL(expr, "Property Failed: Did not satisfy", BSL_ERR_FAILURE);

#define CHK_POSTCONDITION(expr) CHK_TEMPL(expr, "Postcondition Failed: Did not satisfy", BSL_ERR_FAILURE);

#define ASSERT_TEMPL(expr, msg)                 \
    do                                          \
    {                                           \
        if (!(expr))                            \
        {                                       \
            BSL_LOG_ERR("" msg " (" #expr ")"); \
            assert(!(expr));                    \
        }                                       \
    }                                           \
    while (0)

#define ASSERT_ARG_EXPR(expr) ASSERT_TEMPL(expr, "Panic: Argument expression check failed to satisfy")

#define ASSERT_ARG_NONNULL(var) ASSERT_TEMPL((var) != NULL, "Panic: Null Argument check failed to satisfy")

#define ASSERT_PROPERTY(expr) ASSERT_TEMPL(expr, "Panic: Property check failed to satisfy")

#define ASSERT_PRECONDITION(expr) ASSERT_TEMPL(expr, "Panic: Precondition failed to satisfy")

#define ASSERT_POSTCONDITION(expr) ASSERT_TEMPL(expr, "Panic: Precondition failed to satisfy")

// TODO(Bvb): These can be moved to backend, or removed.
/// Data pointer for BSL_Data_t
typedef uint8_t *BSL_DataPtr_t;
/// Pointer to constant data for BSL_Data_t
typedef const uint8_t *BSL_DataConstPtr_t;

/** Heap data storage and views.
 */
typedef struct BSL_Data_s
{
    /// @brief True if this data is a copy
    bool owned;
    /// @brief Pointer to the front of the buffer
    BSL_DataPtr_t ptr;
    /// @brief Size of the data buffer
    size_t len;
} BSL_Data_t;

/** Static initializer for a data store.
 * @sa BSL_Data_Init()
 */
#define BSL_DATA_INIT_NULL                    \
    {                                         \
        .owned = false, .ptr = NULL, .len = 0 \
    }

/** Initialize an empty data struct.
 *
 * @param[in,out] data The data to initialize, which must not be NULL.
 * @return Zero upon success.
 * @sa BSL_DATA_INIT_NULL
 */
int BSL_Data_Init(BSL_Data_t *data);

/** Initialize with an owned buffer of size bytelen
 *
 * @todo Clarify to indicate this calls MALLOC.
 *
 * @param[in,out] data The data to initialize.
 * @param[in] bytelen Length of buffer to allocate.
 * @return Zero upon success.
 */
int BSL_Data_InitBuffer(BSL_Data_t *data, size_t bytelen);

/** Initialize a data struct as an overlay on optional external data.
 *
 * @param[in,out] data The data to initialize, which must not be NULL.
 * @param[in] len The total length to allocate, which may be zero.
 * @param[in] src An optional source buffer to point to.
 * @return Zero upon success.
 */
int BSL_Data_InitView(BSL_Data_t *data, size_t len, BSL_DataPtr_t src);

/// @overload
void BSL_Data_InitMove(BSL_Data_t *data, BSL_Data_t *src);

/** De-initialize a data struct, freeing if necessary.
 *
 * @param[in,out] data The data to de-initialize, which must not be NULL.
 * @return Zero upon success.
 * @post The struct must be initialized before using again.
 */
int BSL_Data_Deinit(BSL_Data_t *data);

/** Resize the data, copying if necessary.
 *
 * @param[in,out] data The data to resize, which must not be NULL.
 * @param[in] len The new total size.
 * @return Zero upon success.
 */
int BSL_Data_Resize(BSL_Data_t *data, size_t len);

/** Set an initialized data struct to a given size.
 *
 * @param[in,out] data The data to copy into, which must not be NULL.
 * @param[in] len The total length to allocate, which may be non-zero.
 * @param[in] src An optional source buffer to copy from, from which @c len
 * bytes will be copied.
 * @return Zero upon success.
 */
int BSL_Data_CopyFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src);

/** Append an initialized data struct with a given size.
 *
 * @param[in,out] data The data to copy into, which must not be NULL.
 * @param[in] len The total length to allocate, which may be non-zero.
 * @param[in] src An optional source buffer to copy from, from which @c len
 * bytes will be copied.
 * @return Zero upon success.
 */
int BSL_Data_AppendFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src);

/// @brief Forward declaration for file-like sequential reader.
typedef struct BSL_SeqReader BSL_SeqReader_t;

/** Release resources from a sequential reader.
 *
 * @param[in,out] obj The reader handle.
 * @return Zero if successful.
 */
int BSL_SeqReader_Deinit(BSL_SeqReader_t *obj);

/** Iterate a sequential reader.
 *
 * @param[in,out] obj The reader handle.
 * @param[out] buf The output buffer to fill.
 * @param[in,out] bufsize The available output buffer size as input,
 * set to the used buffer size as output.
 * @return Zero if successful.
 */
int BSL_SeqReader_Get(BSL_SeqReader_t *obj, uint8_t *buf, size_t *bufsize);

/// @brief Forward-declaration for file-like interface for a sequential writer.
typedef struct BSL_SeqWriter BSL_SeqWriter_t;

/** Release resources from a sequential writer.
 *
 * @param[in,out] obj The writer handle.
 * @return Zero if successful.
 */
int BSL_SeqWriter_Deinit(BSL_SeqWriter_t *obj);

/** Iterate a sequential writer.
 *
 * @param obj The writer handle.
 * @param[in] buf The input buffer to copy from.
 * @param[in,out] bufsize The available input buffer size as input,
 * set to the used buffer size as output.
 * @return Zero if successful.
 */
int BSL_SeqWriter_Put(BSL_SeqWriter_t *obj, const uint8_t *buf, size_t *bufsize);

/** Static initializer for an invalid ::BSL_HostEID_t.
 * Even after this, BSL_HostEID_Init() must be used to get into a valid state.
 */
#define BSL_HOSTEID_INIT_INVALID \
    {                            \
        .handle = NULL           \
    }

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
/** Static initializer for an invalid ::BSL_HostEIDPattern_t.
 * Even after this, BSL_HostEIDPattern_Init() must be used to get into a valid state.
 */
#define BSL_HOSTEID_INIT_INVALID \
    {                            \
        .handle = NULL           \
    }

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
 * @param[in] eid
 * @param[in] user_data
 * @return Zero if successful.
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

/** Block types using IANA-assigned code points from @cite iana:bundle.
 */
typedef enum
{
    /// @brief Primary block ID (a special case)
    BSL_BLOCK_TYPE_PRIMARY = 0,
    /// @brief Payload block
    BSL_BLOCK_TYPE_PAYLOAD                 = 1,
    BSL_BLOCK_TYPE_BUNDLE_AUTH             = 2,
    BSL_BLOCK_TYPE_PAYLOAD_INTEGRITY       = 3,
    BSL_BLOCK_TYPE_PAYLOAD_CONFIDENTIALITY = 4,
    BSL_BLOCK_TYPE_PREVIOUS_HOP_INSERTION  = 5,
    BSL_BLOCK_TYPE_PREVIOUS_NODE           = 6,
    BSL_BLOCK_TYPE_BUNDLE_AGE              = 7,
    BSL_BLOCK_TYPE_METADATA_EXT            = 8,
    BSL_BLOCK_TYPE_EXT_SECURITY            = 9,
    BSL_BLOCK_TYPE_HOP_COUNT               = 10,
    /// @brief Block Integrity @cite iana:bundle
    BSL_BLOCK_TYPE_BIB = 11,
    /// @brief Block Confidentiality @cite iana:bundle
    BSL_BLOCK_TYPE_BCB = 12,
} BSL_BundleBlockTypeCode_e;

/** Flags of the Abstract Security Block @cite rfc9172.
 */
typedef enum
{
    /// @brief Flag set when parameters are present
    BSL_ASB_FLAG_PARAMS = 1
} BSL_BundleASBFlag_e;

/** Creation Timestamp
 *  Defined in Section 4.2.7 of RFC 9171 @cite rfc9171
 */
typedef struct BSL_BundleTimestamp_s
{
    /// @brief Creation timestamp DTN creation time
    uint64_t bundle_creation_time;
    /// @brief Creation timestamp sequence number
    uint64_t seq_num;
} BSL_BundleTimestamp_t;

/** Bundle processing control flags.
 * Defined in Section 4.2.3 of RFC 9171 @cite rfc9171.
 */
typedef enum
{
    /// Set if this bundle is a fragment
    BSL_BUNDLE_IS_FRAGMENT = 0x0001,
    // Others TBD
} BSL_BundleCtrlFlag_e;

/** @brief Calls the host interface to get a bundle primary block information.abort
 *
 * @param[in]       bundle Bundle context
 * @param[out]   result_primary_block Non-null pointer to result which gets populated on a zero return code.
 * @return 0 on success, negative on error
 */
int BSL_BundleCtx_GetBundleMetadata(const BSL_BundleRef_t *bundle, BSL_PrimaryBlock_t *result_primary_block);

/** @brief Returns an array in which each element contains the id of the corresponding block.abort
 *
 * @param[in] bundle    Bundle context
 * @param[in] array_count   Number of elements in `block_id_index_array`
 * @param[out] block_id_index_array Array of `array_count` elements for results
 * @param[out] result_count Contains the number of elements put into the array
 * @return 0 on success, negative on error
 */
int BSL_BundleCtx_GetBlockIds(const BSL_BundleRef_t *bundle, size_t array_count, uint64_t block_ids_array[array_count],
                              size_t *result_count);

/** @brief Returns information about the bundle Canonical block
 *
 * @param[in] bundle Context bundle
 * @param[in] block_num The number of the bundle canonical block we seek information on
 * @param[out] result_block Pointer to allocated memory which contains the results of the query.
 * @return 0 on success, negative on error
 */
int BSL_BundleCtx_GetBlockMetadata(const BSL_BundleRef_t *bundle, uint64_t block_num,
                                   BSL_CanonicalBlock_t *result_block);

/** @brief Request the creation of a new block of a given type in the bundle
 *
 * @param[in] bundle    Context bundle
 * @param[in] block_type_code The type of block to be created (e.g, 1 means payload)
 * @param[out] block_num Pointer to integer containing the number of the block just created.abort
 * @return 0 on success, negative on error
 */
int BSL_BundleCtx_CreateBlock(BSL_BundleRef_t *bundle, uint64_t block_type_code, uint64_t *block_num);

/** @brief Requests the removal of a block from a bundle
 *
 * @param[in] bundle    Context bundle
 * @param[in] block_num Block number to be removed
 * @return 0 on success, negative on failure.
 */
int BSL_BundleCtx_RemoveBlock(BSL_BundleRef_t *bundle, uint64_t block_num);

/** @brief Requests the re-allocation of a block's BTSD, useful for BCB.
 *
 * @note Uses semantics similar to memcpy.
 *
 * @param[in] bundle Context bundle
 * @param[in] block_num Number of block requesting re-allocated of BTSD
 * @param[in] bytesize Size of new BTSD
 * @return 0 on success, negative on failure.
 */
int BSL_BundleCtx_ReallocBTSD(BSL_BundleRef_t *bundle, uint64_t block_num, size_t bytesize);

#define BSL_DEFAULT_BYTESTR_LEN (128)

/** @brief Security role of an operation
 */
typedef enum
{
    BSL_SECROLE_SOURCE = 1000, ///< Source producing the security result
    BSL_SECROLE_VERIFIER,      ///< Only check the security result.
    BSL_SECROLE_ACCEPTOR       ///< Check and then remove the security result if correct.
} BSL_SecRole_e;

#define BSL_SECROLE_ISVALID(role_value) (((role_value) >= BSL_SECROLE_SOURCE) && ((role_value) <= BSL_SECROLE_ACCEPTOR))

/**
 * RFC 9172-specified block type codes for BIB and BCB.
 * @todo Consider making an RFC9172 header file.
 */
typedef enum
{
    BSL_SECBLOCKTYPE_BIB = 11, ///< RFC9172 code for BIB
    BSL_SECBLOCKTYPE_BCB = 12  ///< RFC9172 code for BCB
} BSL_SecBlockType_e;

/// @brief Helper to determine if a given block type is security
#define BSL_SecBlockType_IsSecBlock(block_id) \
    (((block_id) >= BSL_SECBLOCKTYPE_BIB) && ((block_id) <= BSL_SECBLOCKTYPE_BCB))

/// @brief Represents a security result, being a 2-tuple of (result-id, bytes).
typedef struct BSL_SecResult_s BSL_SecResult_t;

/** Populate a pre-allocated SecResult.
 *
 * @param[in,out] self Non-NULL pointer to allocated result.
 * @param[in] result_id Result ID of corresponding result bytestring, meaning dependent on security context.
 * @param[in] context_id ID of security context.
 * @param[in] target_block_num Target of the given security result, included here for convenience.
 * @param[in] content Read-only view to data containing the bytes of the security result, which is copied out of here.
 * @return 0 on success, negative on error
 */
int BSL_SecResult_Init(BSL_SecResult_t *self, uint64_t result_id, uint64_t context_id, uint64_t target_block_num,
                       BSL_Data_t content);

/** Return true when internal invariant checks pass
 *
 * @param self This security result
 */
bool BSL_SecResult_IsConsistent(const BSL_SecResult_t *self);

/// @brief Returns size in bytes of BSL_SecResult_t
size_t BSL_SecResult_Sizeof(void);

/** @brief Security parameters defined in RFC9172 may be unsigned integers or bytestrings
 *
 */
enum BSL_SecParam_Types_e
{
    BSL_SECPARAM_TYPE_UNKNOWN = 0, ///< Inidcates parsed value not of expected type.
    BSL_SECPARAM_TYPE_INT64,       ///< Indicates value type is an unsigned integer.
    BSL_SECPARAM_TYPE_BYTESTR,     ///< Indicates the value type is a byte string.
    BSL_SECPARAM_TYPE_STR
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
    BSL_SECPARAM_TYPE_KEY_ID,

    /// @brief Used by tests to pass in a specific key bytestring
    BSL_SECPARAM_TYPE_INT_FIXED_KEY,

    /// @brief This must be explicitly set, and set to 0, to avoid generating a wrapped key.
    BSL_SECPARAM_TYPE_INT_USE_WRAPPED_KEY,

    BSL_SECPARAM_TYPE_AUTH_TAG,

    BSL_SECPARAM_TYPE_IV,

    /// @brief Do not use. Indicates final index of internal param ids.
    BSL_SECPARAM_TYPE_INT_ENDINDEX
} BSL_SecParam_InternalIds;

/** Represents a security parameter in an ASB as defined in RFC9172.
 * In an encoded ASB, these are tuples of (param-id, param-val)
 */
typedef struct BSL_SecParam_s BSL_SecParam_t;

/// @brief Get parameter ID of this param
/// @param[in] self This BPSec Param type
/// @return
uint64_t BSL_SecParam_GetId(const BSL_SecParam_t *self);

/** @brief Return true if invariant conditions pass
 * @param[in] self This security parameter
 * @return true if valid, false otherwise.
 */
bool BSL_SecParam_IsConsistent(const BSL_SecParam_t *self);

/** Indicates true when this parameter is NOT an implementation-specific security paramter.
 *
 * @todo Rename to avoid using negative logic and clarify.
 * @param param_id ID of the parameter
 * @return True when this is NOT an internal parameter ID.
 */
bool BSL_SecParam_IsParamIDOutput(uint64_t param_id);

/// @brief Return size of BSL_SecParam_t struct type
size_t BSL_SecParam_Sizeof(void);

/** Initialize as a parameter containing a bytestring.
 *
 * @param[in,out] self This Security Paramter
 * @param[in] param_id ID of the parameter
 * @param[in] value View of bytes, which get copied into this Security Parameter.
 * @return Negative on an error.
 */
int BSL_SecParam_InitBytestr(BSL_SecParam_t *self, uint64_t param_id, BSL_Data_t value);

/** Initialize as a parameter containing an integer as a value.
 *
 * @param[in,out] self This Security Paramter
 * @param[in] param_id ID of the parameter
 * @param[in] value View of bytes, which get copied into this Security Parameter.
 * @return Negative on an error.
 */
int BSL_SecParam_InitInt64(BSL_SecParam_t *self, uint64_t param_id, uint64_t value);

/**
 * @param[in,out] self This Security Paramter
 * @param[in] param_id ID of the parameter
 * @param[in] value text string of the parameter, copied into self
 * @return Negative on an error.
 */
int BSL_SecParam_InitStr(BSL_SecParam_t *self, uint64_t param_id, const char *value);

/** Returns true when the value type is an integer.
 *
 * @param[in] self This Security Parameter
 * @return True when value type is integer.
 */
int BSL_SecParam_IsInt64(const BSL_SecParam_t *self);

/** Retrieve integer value of result when this result type is integer. WARNING: Always check using BSL_SecParam_IsInt64
 * first.
 *
 * @param[in] self This Security Parameter
 * @return Integer value of parameter if present, panics/aborts otherwise.
 */
uint64_t BSL_SecParam_GetAsUInt64(const BSL_SecParam_t *self);

/** Retrieve bytestring value of result when security parameter type is bytestring. WARNING: Always check type before
 * using.
 *
 * @todo Clarify whether result contains copy or view of content
 * @param[in] self This Security Parameter
 * @param[in,out] result Pointer to pre-allocated data into which the bytestring is copied.
 * @return Negative on error.
 */
int BSL_SecParam_GetAsBytestr(const BSL_SecParam_t *self, BSL_Data_t *result);

/** Represents a Security Operation produced by a policy provider to inform the security context.
 *
 */
typedef struct BSL_SecOper_s BSL_SecOper_t;

size_t BSL_SecOper_Sizeof(void);

/** Populate a pre-allocated Security Operation with the given values.
 *
 * @param[in,out] self Non-NULL pointer to this security operation.
 * @param[in] context_id ID of the security context
 * @param[in] target_block_num Block ID of security target block
 * @param[in] sec_block_num Block ID of security block.
 * @param[in] sec_type Member of BSL_SecBlock_Type_e enum indicating BIB or BCB
 * @param[in] sec_role Member of BSL_SecRole_e enum indicating role.
 */
void BSL_SecOper_Init(BSL_SecOper_t *self, uint64_t context_id, uint64_t target_block_num, uint64_t sec_block_num,
                      BSL_SecBlockType_e sec_type, BSL_SecRole_e sec_role, BSL_PolicyAction_e failure_code);

/** Empty and release any resources used internally by this structure.
 *
 * Certain backend implementations may create dynamic data structures that may need to be cleaned up,
 * so it is essential to call this under all circumstances.
 *
 * @param[in,out] self Non-NULL pointer to this security operation
 */
void BSL_SecOper_Deinit(BSL_SecOper_t *self);

/** Returns true if internal consistency and sanity checks pass
 *
 * @todo Formalize invariants
 * @param[in] self This security operation
 * @return True if consistent, may assert false otherwise.
 */
bool BSL_SecOper_IsConsistent(const BSL_SecOper_t *self);

/** Returns a pointer to the Security Parameter at a given index in the list of all paramters.
 * @todo Clarify behavior if index is out of range.
 * @param[in] self This security operation
 * @param[in] index Index of security paramter list to retrieve from
 * @return Pointer to security parameter type at given index.
 */
const BSL_SecParam_t *BSL_SecOper_GetParamAt(const BSL_SecOper_t *self, size_t index);

/// @brief Get the block number of the security block containing this sec operation
/// @param[in] self This security operation
uint64_t BSL_SecOper_GetSecurityBlockNum(const BSL_SecOper_t *self);

/// @brief Get the block number of the target block covered by this security operation
/// @param[in] self This security operation
uint64_t BSL_SecOper_GetTargetBlockNum(const BSL_SecOper_t *self);

/** Get the count of parameters contained within this security operation.
 *
 * @param self This security operation.
 * @return Count of security parameters.
 */
size_t BSL_SecOper_CountParams(const BSL_SecOper_t *self);

/** Add the given security parameter to this list of parameters.
 * @todo Clarify pointer/copy semantics.
 * @param[in,out] self This security operation
 * @param[in] param Security parameter to include.
 */
void BSL_SecOper_AppendParam(BSL_SecOper_t *self, const BSL_SecParam_t *param);

/** Return true if this security operation's role is SOURCE
 * @param[in] self This Security Operation
 * @return boolean
 */
bool BSL_SecOper_IsRoleSource(const BSL_SecOper_t *self);

/** Return true if this security operation's role is Verifier
 * @param[in] self This Security Operation
 * @return boolean
 */
bool BSL_SecOper_IsRoleVerifier(const BSL_SecOper_t *self);

/** Return true if this security operation's role is Acceptor
 * @param[in] self This Security Operation
 * @return boolean
 */
bool BSL_SecOper_IsRoleAcceptor(const BSL_SecOper_t *self);

/** Return true if this security operation is BIB
 * @param[in] self This security operation
 * @return boolen
 */
bool BSL_SecOper_IsBIB(const BSL_SecOper_t *self);

/// Forward declaration of BSL_AbsSecBlock_t
typedef struct BSL_AbsSecBlock_s BSL_AbsSecBlock_t;

/// @brief Returns the size of the AbsSecBlock struct in bytes
/// @return size of AbsSecBlock struct
size_t BSL_AbsSecBlock_Sizeof(void);

/** Populate a pre-allocated Absract Security Block
 * @todo - Can be backend-only.
 *
 * @param[in,out] self This ASB
 * @param[in] sec_context_id Security Context ID
 * @param[in] source_eid Source EID in format native to host BPA.
 */
void BSL_AbsSecBlock_Init(BSL_AbsSecBlock_t *self, uint64_t sec_context_id, BSL_HostEID_t source_eid);

/** Checks internal consistency and sanity of this structure.
 * @param[in] self This ASB
 */
bool BSL_AbsSecBlock_IsConsistent(const BSL_AbsSecBlock_t *self);

/** Initialize a pre-allocated ASB with no contents.
 * @param[in,out] self This ASB
 */
void BSL_AbsSecBlock_InitEmpty(BSL_AbsSecBlock_t *self);

/** Deinitializes and clears this ASB, clearing and releasing any owned memory.
 *
 * @param[in,out] self This ASB
 */
void BSL_AbsSecBlock_Deinit(BSL_AbsSecBlock_t *self);

/** Prints to LOG INFO
 * @todo - Can be backend-only.
 *
 * @param[in] self This ASB
 * @todo Refactor to dump this to a pre-allocated string.
 */
void BSL_AbsSecBlock_Print(const BSL_AbsSecBlock_t *self);

/** Returns true if this ASB contains nothing (i.e., no tarets, params and results)
 *
 * @param[in] self This ASB.
 * @return true if ASB is empty
 */
bool BSL_AbsSecBlock_IsEmpty(const BSL_AbsSecBlock_t *self);

/** Returns true if a given ASB contains the given block number as a security target.
 *
 * @param[in,out] self This ASB.
 * @param[in] target_block_num ID of a block, 0 indicates primary block
 * @return true if ASB contains target
 */
bool BSL_AbsSecBlock_ContainsTarget(const BSL_AbsSecBlock_t *self, uint64_t target_block_num);

/** Adds a given block ID as a security target covered by this ASB
 * @todo - Can be backend-only.
 *
 * @param[in,out] self This ASB.
 * @param[in] target_block_id ID of a block, 0 indicates primary block as usual.
 */
void BSL_AbsSecBlock_AddTarget(BSL_AbsSecBlock_t *self, uint64_t target_block_id);

/** Add a security parameter to this security block (does NOT copy)
 * @todo - Can be backend-only.
 *
 * @param[in,out] self This security block
 * @param[in] param Non-Null Security parameter pointer to add to list
 */
void BSL_AbsSecBlock_AddParam(BSL_AbsSecBlock_t *self, const BSL_SecParam_t *param);

/** Add a security result to this security block (does NOT copy)
 *
 * @todo - Can be backend-only.
 *
 * @param[in,out] self This security block
 * @param[in] result Non-Null Security result pointer to add to list
 */
void BSL_AbsSecBlock_AddResult(BSL_AbsSecBlock_t *self, const BSL_SecResult_t *result);

/** Remove security parameters and results found in `outcome` from this ASB
 *
 * @todo - Can be backend-only.
 *
 * @param[in,out] self This ASB
 * @param[in] outcome Security Operation outcome containing params and results
 * @return Negative on error, otherwise count of things removed.
 */
int BSL_AbsSecBlock_StripResults(BSL_AbsSecBlock_t *self, uint64_t target_block_num);

/** Encodes this ASB into a CBOR string into the space pre-allocated indicated by the argument.
 *
 * @param[in] self This ASB.
 * @param[in] buf A buffer with allocated space for the encoded CBOR
 * or the @c SizeCalculateUsefulBuf value to get the real size.
 * @return Integer contains number of bytes written to buffer, negative indicates error.
 *
 */
ssize_t BSL_AbsSecBlock_EncodeToCBOR(const BSL_AbsSecBlock_t *self, UsefulBuf buf);

/** Decodes and populates this ASB from a CBOR string.
 *
 * @param[in,out] self This allocated, but uninitialized ASB to populate.
 * @param[in] encoded_cbor A buffer containing a CBOR string representing the ASB
 * @return Negative on error
 */
int BSL_AbsSecBlock_DecodeFromCBOR(BSL_AbsSecBlock_t *self, BSL_Data_t encoded_cbor);

/** @brief Represents the output following execution of a security operation.
 */
typedef struct BSL_SecOutcome_s BSL_SecOutcome_t;

/// @brief Returns the size of the BSL_SecOutcome_t structure.
size_t BSL_SecOutcome_Sizeof(void);

/** Populate a pre-allocated security outcome struct.
 *
 * @param[in,out] self Non-Null pointer to this security outcome.
 * @param[in] sec_oper Security operation containing the necessary info.
 * @param[in] allocation_size Size of working space to allocate.
 */
void BSL_SecOutcome_Init(BSL_SecOutcome_t *self, const BSL_SecOper_t *sec_oper, size_t allocation_size);

/** Release any resources owned by this security outcome.
 *
 * @param[in,out] self Non-Null pointer to this security outcome.
 */
void BSL_SecOutcome_Deinit(BSL_SecOutcome_t *self);

/** Return true if internal invariants hold
 *
 * @param[in] self This sec outcome.
 * @return true if invariants hold
 */
bool BSL_SecOutcome_IsConsistent(const BSL_SecOutcome_t *self);

/** Append a Security Result to this outcome.
 *
 * @todo Double-check copy semantics.
 *
 * @param[in,out] self Non-NULL pointer to this security outcome.
 * @param[in] sec_result Non-NULL pointer to security result to copy and append.
 */
void BSL_SecOutcome_AppendResult(BSL_SecOutcome_t *self, const BSL_SecResult_t *sec_result);

/** Get the result at index i. Panics if i is out of range.
 *
 * @param[in] self This outcome
 * @param[in] index Index in the list to retrieve
 * @return Sec Result at index
 */
const BSL_SecResult_t *BSL_SecOutcome_GetResultAtIndex(const BSL_SecOutcome_t *self, size_t index);

/** Get the number of results
 *
 * @param[in] self this sec outcome
 * @return number of results in sec outcome
 */
size_t BSL_SecOutcome_CountResults(const BSL_SecOutcome_t *self);

/** Append a Security Parameter to this outcome.
 *
 * @todo Double-check copy semantics.
 *
 * @param[in,out] self Non-NULL pointer to this security outcome.
 * @param[in] param Non-NULL pointer to security parameter to copy and append.
 */
void BSL_SecOutcome_AppendParam(BSL_SecOutcome_t *self, const BSL_SecParam_t *param);

/** @brief Returns number of parameters in this outcome.
 * @param[in] self This outcome
 * @return Number of parameters
 */
size_t BSL_SecOutcome_CountParams(const BSL_SecOutcome_t *self);

const BSL_SecParam_t *BSL_SecOutcome_GetParamAt(const BSL_SecOutcome_t *self, size_t index);

/// @brief Returns true if this (the parameters and results) is contained within the given ASK
/// @todo Can move to backend
/// @param[in] self
/// @param[in] outcome
/// @return
bool BSL_SecOutcome_IsInAbsSecBlock(const BSL_SecOutcome_t *self, const BSL_AbsSecBlock_t *abs_sec_block);

/// @brief Returns size of the struct, helpful for dynamic allocation.
/// @return Size of the struct
size_t BSL_SecurityActionSet_Sizeof(void);

/** @brief Initialize a new security action set
 *
 * @param[in,out] self This pre-allocated action set
 */
void BSL_SecurityActionSet_Init(BSL_SecurityActionSet_t *self);

/** @brief Increment a security failure for this action set
 *
 * @param[in,out] self Pointer to this security action set.
 */
void BSL_SecurityActionSet_IncrError(BSL_SecurityActionSet_t *self);

/** @brief Returns count of failures after processing this action set
 *
 * @param[in] self Pointer ot this security action set.
 * @return Count of errors.
 */
size_t BSL_SecurityActionSet_CountErrors(const BSL_SecurityActionSet_t *self);

/** Zeroize, clear, and release itself and any owned resources.
 *
 * @param[in,out] self This action set.
 */
void BSL_SecurityActionSet_Deinit(BSL_SecurityActionSet_t *self);

/** @brief Append a security operation to the security action set
 *
 * @param[in,out] self This security action set.
 * @param[in] sec_oper Security operation to include.
 * @return 0 on success, negative on error
 */
int BSL_SecurityActionSet_AppendSecOper(BSL_SecurityActionSet_t *self, const BSL_SecOper_t *sec_oper);

/** Return true if internal sanity and consistency checks pass
 *
 * @param[in] self This action set.
 * @return true if action set is consistent
 */
bool BSL_SecurityActionSet_IsConsistent(const BSL_SecurityActionSet_t *self);

/** Count number of security operations present in this policy action set.
 *
 * @param[in] self This action set.
 * @return Number of operations, 0 indicates no policy matched.
 */
size_t BSL_SecurityActionSet_CountSecOpers(const BSL_SecurityActionSet_t *self);

/** Returns the Security Operation at the given index.
 *
 * @param[in] self This action set
 * @param[in] index index
 * @return pointer to security operation at given index, asserting false if not in bound
 */
const BSL_SecOper_t *BSL_SecurityActionSet_GetSecOperAtIndex(const BSL_SecurityActionSet_t *self, size_t index);

/** Get the error code after querying (inspecting) policy actions. Non-zero indicates error
 *
 * @param[in] self this action set
 * @return Anomaly on non-zero
 */
int BSL_SecurityActionSet_GetErrCode(const BSL_SecurityActionSet_t *self);

/// @brief Returns size of this struct type
size_t BSL_SecurityResponseSet_Sizeof(void);

/** Initialize with the given count of operations and nailures
 *
 * @todo This is still undefined.
 *
 */
void BSL_SecurityResponseSet_Init(BSL_SecurityResponseSet_t *self, size_t noperations, size_t nfailed);

/** Zeroize itself and release any owned resources
 *
 * @param[in,out] self This response set.
 */
void BSL_SecurityResponseSet_Deinit(BSL_SecurityResponseSet_t *self);

/** Return true if internal consistency checks pass.
 *
 * @param[in] self This response set.
 */
bool BSL_SecurityResponseSet_IsConsistent(const BSL_SecurityResponseSet_t *self);

/** Return number of responses (operations acted upon)
 *
 * @param[in] self This response set.
 */
size_t BSL_SecurityResponseSet_CountResponses(const BSL_SecurityResponseSet_t *self);

/** Queries the policy provider for any security operations to take on the bundle.
 *
 * @note The caller is obligated to allocate space for the policy_action_set output.
 * This memory must be zeroed before being passed, doing otherwise will raise an assertion.
 *
 * @param[in] bsl BSL library context
 * @param[out] output_action_set  policy action set, which may contain error codes and other info. @preallocated
 * Caller-allocated, zeroed space for action set
 * @param[in,out] bundle Bundle seeking security operations
 * @param[in] location Where in the BPA lifecycle this query arises from
 * @return 0 if success
 */
int BSL_PolicyRegistry_InspectActions(const BSL_LibCtx_t *bsl, BSL_SecurityActionSet_t *output_action_set,
                                      const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location);

/** Finalizes policy provider for sec ops & sec results for a bundle
 *
 * @param[in] bsl BSL library context
 * @param[in] policy_actions A policy action set, which may contain error codes and other info. @preallocated
 * Caller-allocated, zeroed space for action set
 * @param[in,out] bundle Bundle seeking security operations
 * @param[in] response_output results from security context
 * @param[in] location Where in the BPA lifecycle this query arises from
 * @return 0 if success
 */
int BSL_PolicyRegistry_FinalizeActions(const BSL_LibCtx_t *bsl, const BSL_SecurityActionSet_t *policy_actions,
                                       const BSL_BundleRef_t *bundle, const BSL_SecurityResponseSet_t *response_output);

/// @brief Callback interface to query policy provider to populate the action set
typedef int (*BSL_PolicyInspect_f)(const void *user_data, BSL_SecurityActionSet_t *output_action_set,
                                   const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location);

/// @brief Callback interface to query policy provider to populate the action set
typedef int (*BSL_PolicyFinalize_f)(const void *user_data, const BSL_SecurityActionSet_t *output_action_set,
                                    const BSL_BundleRef_t *bundle, const BSL_SecurityResponseSet_t *response_output);

/// @brief Callback interface for policy provider to shut down and release any resources
typedef void (*BSL_PolicyDeinit_f)(void *user_data);

/// @brief Descriptor of opaque data and callbacks for Policy Provider.
struct BSL_PolicyDesc_s
{
    void                *user_data;
    BSL_PolicyInspect_f  query_fn;    ///< Function pointer to query policy
    BSL_PolicyFinalize_f finalize_fn; ///< Function pointer to finalize policy
    BSL_PolicyDeinit_f   deinit_fn;   ///< Function to deinit the policy provider at termination of BPA.
};

/** Call the underying security context to perform the given action
 *
 * @param[in] lib This BSL context
 * @param[out] output_response Pointer to allocated, zeroed memory into which the response is populated
 * @param[in,out] bundle Pointer to bundle, which may be modified.
 * @param[in] action_set Action containing all params and operations.
 * @return 0 on success, negative on failure.
 */
int BSL_SecCtx_ExecutePolicyActionSet(BSL_LibCtx_t *lib, BSL_SecurityResponseSet_t *output_response,
                                      BSL_BundleRef_t *bundle, const BSL_SecurityActionSet_t *action_set);

/**
 * @todo Doxygen
 */
bool BSL_SecCtx_ValidatePolicyActionSet(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle,
                                        const BSL_SecurityActionSet_t *action_set);

/** Signature for Security Context validator for a sec OP.
 *
 * @param[in] lib The library context.
 * @param[in] bundle The bundle to inspect.
 * @param[in] sec_oper The security operation to perform.
 * @return True if security operation is deemed valid.
 */
typedef bool (*BSL_SecCtx_Validate_f)(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper);

/** Signature for Security Context executor for a sec OP.
 *
 * @param[in] lib The library context.
 * @param[in,out] bundle The bundle to modify.
 * @param[in] sec_oper The security operation to perform.
 * @param[in,out] sec_outcome The pre-allocated outcome to populate
 * @return 0 if security operation performed successfully.
 */
typedef int (*BSL_SecCtx_Execute_f)(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                                    BSL_SecOutcome_t *sec_outcome);

/** @brief Security Context descriptor (interface)
 */
struct BSL_SecCtxDesc_s
{
    /// @brief User data pointer for callbacks
    void *user_data;
    /// @brief Callback to validate a sec op within a given bundle
    BSL_SecCtx_Validate_f validate;
    /// @brief Callback to execute a sec op within a given bundle
    BSL_SecCtx_Execute_f execute;
};

#endif /* BSL_BPSECLIB_PRIVATE_H_ */
