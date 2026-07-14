/*
 * Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
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
 * more reach into the BSL, without requiring any of them to have specific dependencies on the other. The Host BPA
 * should only need the purely public header file.
 *
 * @author Bill.Van.Besien@jhuapl.edu
 */

#ifndef BSL_BPSECLIB_PRIVATE_H_
#define BSL_BPSECLIB_PRIVATE_H_

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>

#include "BPSecLib_Public.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    BSL_ERR_POLICY_QUERY  = -101, ///< Error code for errors arising from Policy Provider query
    BSL_ERR_POLICY_FINAL  = -102, ///< Error code for errors arising from Policy Provider finalize
    BSL_ERR_POLICY_CONFIG = -103, ///< Error code for errors arising from Policy Provider configuration

    /// Security Context errors start at 200
    BSL_ERR_SECURITY_CONTEXT_FAILED       = -200, ///< General error code for errors arising from a Security Context.
    BSL_ERR_SECURITY_CONTEXT_PARTIAL_FAIL = -201, ///< General code where at least some security operations failed.
    BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED = -202, ///< Indicates security context validate failed
    BSL_ERR_SECURITY_CONTEXT_AUTH_FAILED       = -203, ///< Indicates an HMAC Auth failed
    BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED     = -204  ///< Indicates a cryptographic operation failed (encrypt/decrypt)
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
 * @param cond The condition to check.
 * @param val The return value if the check fails.
 * @deprecated
 */
#define BSL_CHKRET(cond, val) \
    if (!LIKELY(cond))        \
    {                         \
        return val;           \
    }
/// Return from void functions if condition fails.
#define BSL_CHKVOID(cond) BSL_CHKRET(cond, )
/// Return a null pointer if condition fails.
#define BSL_CHKNULL(cond) BSL_CHKRET(cond, NULL)
/// Return false if condition fails.
#define BSL_CHKFALSE(cond) BSL_CHKRET(cond, false)
/// Return the error value 1 if condition fails.
#define BSL_CHKERR1(cond) BSL_CHKRET(cond, 1)
/** Check a value for non-zero and return that value.
 * @warning The parameter is evaluated twice so should be a simple variable.
 *
 * @param value The value to check and conditionally return.
 */
#define BSL_CHKERRVAL(value) BSL_CHKRET(!(value), (value))

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

/** Determine if a particular severity is being logged.
 * This function is multi-thread safe.
 *
 * @param severity The severity from a subset of the POSIX syslog values.
 * @return True if the severity level will be logged.
 * @sa BSL_log_set_least_severity()
 */
bool BSL_LogIsEnabledFor(int severity);

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

/** @brief Helpful macros for expressing invariants, pre/post conditions, and arg validation.
 * The expression is nominally true and only false during exceptional cases.
 */
#define CHK_TEMPL(expr, msg, return_code)                                 \
    do                                                                    \
    {                                                                     \
        if (!LIKELY(expr))                                                \
        {                                                                 \
            BSL_LOG_ERR("%s (%s) [errcode=%d]", msg, #expr, return_code); \
            return return_code;                                           \
        }                                                                 \
    }                                                                     \
    while (0) /* GCOV_EXCL_LINE */

/** Check a condition and return false if the condition is false.
 * @param expr The condition which normally evaluates to true.
 */
#define CHK_AS_BOOL(expr) CHK_TEMPL(expr, "Failed Property Check: Failed to satisfy", false)

#define CHK_ARG_EXPR(expr) \
    CHK_TEMPL(expr, "Illegal Argument: Argument expression check failed to satisfy", BSL_ERR_ARG_INVALID)

#define CHK_ARG_NONNULL(var) \
    CHK_TEMPL((var) != NULL, "Illegal Argument: Argument null check failed to satisfy", BSL_ERR_ARG_NULL)

#define CHK_PRECONDITION(expr) CHK_TEMPL(expr, "Precondition Failed: Did not satisfy", BSL_ERR_FAILURE)

#define CHK_PROPERTY(expr) CHK_TEMPL(expr, "Property Failed: Did not satisfy", BSL_ERR_FAILURE)

#define CHK_POSTCONDITION(expr) CHK_TEMPL(expr, "Postcondition Failed: Did not satisfy", BSL_ERR_FAILURE)

#define ASSERT_TEMPL(expr, msg)                                                    \
    do                                                                             \
    {                                                                              \
        if (!LIKELY(expr))                                                         \
        {                                                                          \
            fprintf(stderr, "At %s:%d %s (%s)\n", __FILE__, __LINE__, msg, #expr); \
            abort();                                                               \
        }                                                                          \
    }                                                                              \
    while (0)

#define ASSERT_ARG_EXPR(expr) ASSERT_TEMPL(expr, "Panic: Argument expression check failed to satisfy")

#define ASSERT_ARG_NONNULL(var) ASSERT_TEMPL((var) != NULL, "Panic: Null Argument check failed to satisfy")

#define ASSERT_PROPERTY(expr) ASSERT_TEMPL(expr, "Panic: Property check failed to satisfy")

#define ASSERT_PRECONDITION(expr) ASSERT_TEMPL(expr, "Panic: Precondition failed to satisfy")

#define ASSERT_POSTCONDITION(expr) ASSERT_TEMPL(expr, "Panic: Precondition failed to satisfy")

// Forward declaration for file-like sequential reader.
typedef struct BSL_SeqReader_s BSL_SeqReader_t;

/** Release resources from a sequential reader.
 * This also frees memory of the instance itself.
 *
 * @param[in,out] obj The reader handle.
 */
void BSL_SeqReader_Destroy(BSL_SeqReader_t *obj);

/** Iterate a sequential reader.
 *
 * @param[in,out] obj The reader handle.
 * @param[out] buf The output buffer to fill.
 * @param[in,out] bufsize The available output buffer size as input,
 * set to the used buffer size as output.
 * @return Zero if successful.
 */
int BSL_SeqReader_Get(BSL_SeqReader_t *obj, uint8_t *buf, size_t *bufsize);

// Forward-declaration for file-like interface for a sequential writer.
typedef struct BSL_SeqWriter_s BSL_SeqWriter_t;

/** Release resources from a sequential writer and possibly commit the writes.
 * This also frees memory of the instance itself.
 *
 * @param[in,out] obj The writer handle.
 * @param success Set true if all of the writing succeeded.
 */
void BSL_SeqWriter_Destroy(BSL_SeqWriter_t *obj, bool success);

/** Iterate a sequential writer.
 *
 * @param obj The writer handle.
 * @param[in] buf The input buffer to copy from.
 * @param[in,out] bufsize The available input buffer size as input,
 * set to the used buffer size as output.
 * @return Zero if successful.
 */
int BSL_SeqWriter_Put(BSL_SeqWriter_t *obj, const uint8_t *buf, size_t bufsize);

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
 */
void BSL_HostEID_Init(BSL_HostEID_t *eid);

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

/** Decode an EID from CBOR.
 *
 * @param[in] encoded_bytes CBOR encoded bytes
 * @param[in,out] eid The value to decode into
 * @return 0 on success
 */
int BSL_HostEID_DecodeFromCBOR(const BSL_Data_t *encoded_bytes, BSL_HostEID_t *eid);

/** Encode a EID into CBOR.
 * Either one of @c encoded_bytes or @c encoded_size must be non-NULL.
 *
 * @param[in] eid The value to encode
 * @param[out] encoded_bytes The CBOR encoded bytes output.
 * The structure must already be initialized.
 * @param[out] encoded_size The encoded size needed output.
 * @return Zero if successful.
 */
int BSL_HostEID_EncodeToCBOR(const BSL_HostEID_t *eid, BSL_Data_t *encoded_bytes, size_t *encoded_size);

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
 * @param[out]   result_primary_block Non-null pointer to result which gets initialized and populated on a zero return
 * code.
 * @return 0 on success, negative on error
 */
int BSL_BundleCtx_GetBundleMetadata(const BSL_BundleRef_t *bundle, BSL_PrimaryBlock_t *result_primary_block);

/** @brief Returns information about the bundle Canonical block
 *
 * @param[in] bundle Context bundle
 * @param[in] block_num The number of the bundle canonical block we seek information on
 * @param[out] result_block Pointer to result which gets initialized and populated on a zero return code. Contains
 * results of the query.
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

/** @brief Requests dropping of bundle
 *
 * @param[in] bundle    Context bundle
 * @param[in] reason_code reason code indicating reason for bundle deletion
 * @return 0 on success, negative on failure.
 */
int BSL_BundleCtx_DeleteBundle(BSL_BundleRef_t *bundle, BSL_ReasonCode_t reason_code);

/** @brief Requests the re-allocation of a block's BTSD, useful for BCB.
 *
 * @note Uses semantics similar to @c memcpy().
 *
 * @param[in] bundle Context bundle
 * @param[in] block_num The unique block number for which BTSD will be resized.
 * @param[in] btsd_size Size of new BTSD content.
 * @return 0 on success, negative on failure.
 */
int BSL_BundleCtx_ReallocBTSD(BSL_BundleRef_t *bundle, uint64_t block_num, size_t btsd_size);

/** Construct a new sequential reader for BTSD content.
 *
 * @param[in] bundle Context bundle
 * @param[in] block_num The unique block number for which BTSD will be read from.
 * @return Pointer to the new reader or NULL if some failure occurs.
 */
BSL_SeqReader_t *BSL_BundleCtx_ReadBTSD(const BSL_BundleRef_t *bundle, uint64_t block_num);

/** Construct a new sequential writer for BTSD content.
 *
 * @param[in] bundle Context bundle
 * @param[in] block_num The unique block number for which BTSD will be overwritten.
 * @param btsd_size The total total size of BTSD content that will be written.
 * The actual sequence of writes must not exceed this total size or it will be considered an error.
 * If the actual sequence of writes does not reach this size it should be zero-padded and logged
 * as an anomaly.
 * @return Pointer to the new writer or NULL if some failure occurs.
 */
BSL_SeqWriter_t *BSL_BundleCtx_WriteBTSD(BSL_BundleRef_t *bundle, uint64_t block_num, size_t btsd_size);

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

/** @name Variant storage
 */
///@{

/** Represents a security option, parameter, or result within in an ASB.
 * In an encoded ASB, these are tuples of (param-id, param-val)
 */
typedef struct BSL_Variant_s BSL_Variant_t;

/** Initialize to a default empty state.
 * @param[out] self The object to initialize.
 */
void BSL_Variant_Init(BSL_Variant_t *self);

/** Initialize to a copy of another value.
 * @param[out] self The object to initialize.
 * @param[in] src The source of the copy.
 */
void BSL_Variant_InitSet(BSL_Variant_t *self, const BSL_Variant_t *src);

/** De-initialize a parameter.
 * @param[in,out] self The object to deinitialize.
 */
void BSL_Variant_Deinit(BSL_Variant_t *self);

/** Overwrite with a copy of another value.
 * @param[in,out] self The object to overwrite.
 * @param[in] src The source of the copy.
 */
void BSL_Variant_Set(BSL_Variant_t *self, const BSL_Variant_t *src);

/** Move from another value.
 * The other value is left deinitialized.
 * @param[in,out] self The object to overwrite.
 * @param[in] src The source of the copy.
 */
void BSL_Variant_Move(BSL_Variant_t *self, BSL_Variant_t *src);

/** @brief Return true if invariant conditions pass
 * @param[in] self This security parameter
 * @return true if valid, false otherwise.
 */
bool BSL_Variant_IsConsistent(const BSL_Variant_t *self);

/// @brief Return size of ::BSL_Variant_s struct type
size_t BSL_Variant_Sizeof(void);

/** Set to an signed integer value.
 *
 * @param[in,out] self This Security Parameter
 * @param[in] value The value to use.
 */
void BSL_Variant_SetInt64(BSL_Variant_t *self, uint64_t value);

/** Returns true when the value type is an integer.
 *
 * @param[in] self This Security Parameter
 * @return True when value type is integer.
 */
bool BSL_Variant_IsInt64(const BSL_Variant_t *self);

/** Retrieve integer value of result when this result type is integer.
 *
 * @param[in] self This Security Parameter
 * @param[out] out The optional value
 * @return Zero if the value is an integer.
 */
int BSL_Variant_GetAsInt64(const BSL_Variant_t *self, int64_t *out);

/** Initialize as a parameter containing a bytestring.
 *
 * @param[in,out] self This Security Parameter
 * @param[in] value View of bytes, which get copied into this Security Parameter.
 */
void BSL_Variant_SetBytestr(BSL_Variant_t *self, BSL_Data_t value);

/** Returns true when the value type is a byte string.
 *
 * @param[in] self This Security Parameter
 * @return True when value type is byte string.
 */
bool BSL_Variant_IsBytestr(const BSL_Variant_t *self);

/** Retrieve byte string value of a parameter.
 *
 * @param[in] self This Security Parameter
 * @param[out] out Pointer to optional struct which will be made a view onto this parameter value.
 * That view must not outlive this pair instance.
 * @return Negative on error.
 */
int BSL_Variant_GetAsBytestr(const BSL_Variant_t *self, BSL_Data_t *out);

/** Initialize as a parameter containing a byte string with a null-terminated
 * text value.
 *
 * @param[in,out] self This Security Parameter
 * @param[in] value text string of the parameter, copied into self
 */
void BSL_Variant_SetTextstr(BSL_Variant_t *self, const char *value);

/** Returns true when the value type is a text string.
 *
 * @param[in] self This Security Parameter
 * @return True when value type is text string.
 */
bool BSL_Variant_IsTextstr(const BSL_Variant_t *self);

/** Retrieve bytestring value of result when security parameter type is bytestring.
 *
 * @param[in] self This Security Parameter
 * @param[in,out] out Pointer to optional string pointer for view onto this parameter value.
 * That view must not outlive this pair instance.
 * @return Negative on error.
 */
int BSL_Variant_GetAsTextstr(const BSL_Variant_t *self, const char **out);

/** Initialize as a parameter containing raw encoded content.
 *
 * @param[in,out] self This Security Parameter
 * @param[in] ptr The stat of the data.
 * @param len The length to copy.
 */
void BSL_Variant_SetRaw(BSL_Variant_t *self, const void *ptr, size_t len);

/** Returns true when the value type is raw encoded CBOR.
 *
 * @param[in] self This Security Parameter
 * @return True when value type is raw.
 */
bool BSL_Variant_IsRaw(const BSL_Variant_t *self);

/** Retrieve bytestring value of result when security parameter type is bytestring.
 *
 * @param[in] self This Security Parameter
 * @param[out] out Pointer to optional struct which will be made a view onto this parameter value.
 * That view must not outlive this pair instance.
 * @return Negative on error.
 */
int BSL_Variant_GetAsRaw(const BSL_Variant_t *self, BSL_Data_t *out);

///@}

/** Represents a Security Operation produced by a policy provider to inform the security context.
 *
 */
typedef struct BSL_SecOper_s BSL_SecOper_t;

size_t BSL_SecOper_Sizeof(void);

/** Initialize a newly allocated structure.
 *
 * @param[in,out] self Non-NULL pointer to this security operation
 */
void BSL_SecOper_Init(BSL_SecOper_t *self);

/** Initialize from a copy.
 *
 * @param[in,out] self Non-NULL pointer to this security operation
 * @param[in] src Non-NULL pointer to this source to copy from.
 */
void BSL_SecOper_InitSet(BSL_SecOper_t *self, const BSL_SecOper_t *src);

/** Empty and release any resources used internally by this structure.
 *
 * Certain backend implementations may create dynamic data structures that may need to be cleaned up,
 * so it is essential to call this under all circumstances.
 *
 * @param[in,out] self Non-NULL pointer to this security operation
 */
void BSL_SecOper_Deinit(BSL_SecOper_t *self);

/** Set from a copy.
 *
 * @param[in,out] self Non-NULL pointer to this security operation
 * @param[in] src Non-NULL pointer to this source to copy from.
 */
void BSL_SecOper_Set(BSL_SecOper_t *self, const BSL_SecOper_t *src);

/** Populate an initialized Security Operation with the given values.
 *
 * @param[in,out] self Non-NULL pointer to this security operation.
 * @param[in] context_id ID of the security context
 * @param[in] target_block_num Block ID of security target block
 * @param[in] sec_block_num Block ID of security block.
 * @param[in] sec_type Member of ::BSL_SecBlockType_e enum indicating BIB or BCB
 * @param[in] sec_role Member of ::BSL_SecRole_e enum indicating role.
 * @param[in] policy_action Member of ::BSL_PolicyAction_e enum indicating failure policy
 */
void BSL_SecOper_Populate(BSL_SecOper_t *self, int64_t context_id, uint64_t target_block_num, uint64_t sec_block_num,
                          BSL_SecBlockType_e sec_type, BSL_SecRole_e sec_role, BSL_PolicyAction_e policy_action);

/** Returns true if internal consistency and sanity checks pass
 *
 * @param[in] self This security operation
 * @return True if consistent, may assert false otherwise.
 */
bool BSL_SecOper_IsConsistent(const BSL_SecOper_t *self);

/** Get the security source for an operation.
 * If the operation role is source, this is the local security EID, otherwise
 * it is the EID from the ASB from which this operation originated.
 *
 * @return A non-null pointer to the EID struct.
 */
const BSL_HostEID_t *BSL_SecOper_GetSecuritySource(const BSL_SecOper_t *self);

/** Returns a pointer to the Security Parameter at a given index in the list of all parameters.
 *
 * @param[in] self This security operation
 * @param option_id The internal option ID value to search for.
 * @return Pointer to security parameter if found, otherwise NULL.
 */
const BSL_Variant_t *BSL_SecOper_FindOption(const BSL_SecOper_t *self, int64_t option_id);

/** Returns a pointer to the Security Parameter at a given index in the list of all parameters.
 *
 * @param[in] self This security operation
 * @param param_id The parameter ID value to search for.
 * @return Pointer to security parameter if found, otherwise NULL.
 */
const BSL_Variant_t *BSL_SecOper_FindParam(const BSL_SecOper_t *self, int64_t param_id);

/** Count the number of results present.
 * @param[in] self The security operation
 * @return The number of results.
 */
size_t BSL_SecOper_ResultCount(const BSL_SecOper_t *self);

/** Returns a pointer to the Security Parameter at a given index in the list of all parameters.
 *
 * @param[in] self This security operation
 * @param[in] index Index of security parameter list to retrieve from
 * @return Pointer to security result if found, otherwise NULL.
 */
const BSL_Variant_t *BSL_SecOper_FindResult(const BSL_SecOper_t *self, int64_t param_id);

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
size_t BSL_SecOper_CountOptions(const BSL_SecOper_t *self);

/** Add the given option to this operation.
 *
 * @param[in,out] self This security operation
 * @param opt_id The unique option ID.
 * @return A non-null pointer to the option to set.
 */
BSL_Variant_t *BSL_SecOper_AppendOption(BSL_SecOper_t *self, int64_t opt_id);

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
 * @return boolean
 */
bool BSL_SecOper_IsBIB(const BSL_SecOper_t *self);

/**
 * Retrieve the policy action of a security operation
 * @param[in] self The security operation
 * @return the policy action
 */
BSL_PolicyAction_e BSL_SecOper_GetPolicyAction(const BSL_SecOper_t *self);

/**
 * Retrieve the conclusion state of a security operation
 * @param[in] self The security operation
 * @return the conclusion state
 */
BSL_SecOper_ConclusionState_e BSL_SecOper_GetConclusion(const BSL_SecOper_t *self);

/**
 * Set the security operation conclusion state
 * @param[in,out] self security operation to change conclusion state of
 * @param[in] new_conclusion new conclusion to set to
 */
void BSL_SecOper_SetConclusion(BSL_SecOper_t *self, BSL_SecOper_ConclusionState_e new_conclusion);

/**
 * Get security operation reason code
 * @param[in] self the security operation
 * @returns the reason code of the security operation
 */
BSL_ReasonCode_t BSL_SecOper_GetReasonCode(const BSL_SecOper_t *self);

/**
 * Set the security operation reason code
 * @param[in,out] self security operation to change reason code of
 * @param[in] new_reason_code new reason code to set to
 */
void BSL_SecOper_SetReasonCode(BSL_SecOper_t *self, BSL_ReasonCode_t new_reason_code);

// Forward declaration of this struct
typedef struct BSL_AbsSecBlock_s BSL_AbsSecBlock_t;

/// @brief Returns the size of the ::BSL_AbsSecBlock_s struct in bytes
/// @return size of the struct
size_t BSL_AbsSecBlock_Sizeof(void);

/** Populate a pre-allocated Abstract Security Block
 *
 * @param[in,out] self This ASB
 * @param[in] sec_context_id Security Context ID
 */
void BSL_AbsSecBlock_Init(BSL_AbsSecBlock_t *self);

/** Checks internal consistency and sanity of this structure.
 * @param[in] self This ASB
 */
bool BSL_AbsSecBlock_IsConsistent(const BSL_AbsSecBlock_t *self);

/** Deinitializes and clears this ASB, clearing and releasing any owned memory.
 *
 * @param[in,out] self This ASB
 */
void BSL_AbsSecBlock_Deinit(BSL_AbsSecBlock_t *self);

/** Logs events exposing the ASB content at LOG DEBUG severity.
 *
 * @param[in] self This ASB
 */
void BSL_AbsSecBlock_Print(const BSL_AbsSecBlock_t *self);

/** Returns true if this ASB contains no operations (i.e., no targets and results)
 *
 * @param[in] self This ASB.
 * @return true if ASB is empty
 */
bool BSL_AbsSecBlock_IsEmpty(const BSL_AbsSecBlock_t *self);

/** Get the security context ID from a security block.
 *
 * @param[in] self This ASB.
 * @return The context ID integer.
 */
int64_t BSL_AbsSecBlock_GetContextID(const BSL_AbsSecBlock_t *self);

/** Returns true if a given ASB contains the given block number as a security target.
 *
 * @param[in] self This ASB.
 * @param[in] target_block_num ID of a block, 0 indicates primary block
 * @return true if ASB contains target
 */
bool BSL_AbsSecBlock_ContainsTarget(const BSL_AbsSecBlock_t *self, uint64_t target_block_num);

/** Search for a specific security result by its ID.
 *
 * @param[in,out] self This security block
 * @param target_index The target index in the block.
 * This is *not* the block number, it is the zero-based index.
 * @param result_id The result ID to search for.
 * @return Non-null pointer if the result is found.
 */
const BSL_Variant_t *BSL_AbsSecBlock_FindResult(BSL_AbsSecBlock_t *self, uint64_t target_index, uint64_t result_id);

/** Increments a telemetry counter in the ctx based on telemetry index
 */
int BSL_TlmCounters_IncrementCounter(BSL_LibCtx_t *bsl, BSL_TlmCounterIndex_e tlm_index, uint64_t count);

/** @brief Represents the output following execution of a security operation.
 */
typedef struct BSL_SecOutcome_s BSL_SecOutcome_t;

/// @brief Returns the size of the ::BSL_SecOutcome_s structure.
size_t BSL_SecOutcome_Sizeof(void);

/** Populate a pre-allocated security outcome struct.
 *
 * @param[in,out] self Non-Null pointer to this security outcome.
 * @param[in] sec_oper Security operation containing the necessary info.
 */
void BSL_SecOutcome_Init(BSL_SecOutcome_t *self, const BSL_SecOper_t *sec_oper);

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
 * @param[in,out] self Non-NULL pointer to this security outcome.
 * @param result_id The unique result ID.
 * @return Non-NULL pointer to security result just appended.
 */
BSL_Variant_t *BSL_SecOutcome_AppendResult(BSL_SecOutcome_t *self, int64_t result_id);

/** Get the result at index i. Panics if i is out of range.
 *
 * @param[in] self This outcome
 * @param result_id The unique result ID.
 * @return Sec Result pointer if found, or the NULL pointer.
 */
const BSL_Variant_t *BSL_SecOutcome_GetResult(const BSL_SecOutcome_t *self, int64_t result_id);

/** Get the number of results
 *
 * @param[in] self this sec outcome
 * @return number of results in sec outcome
 */
size_t BSL_SecOutcome_CountResults(const BSL_SecOutcome_t *self);

/** Append a Security Parameter to this outcome.
 *
 * @param[in,out] self Non-NULL pointer to this security outcome.
 * @param[in] param_id The unique ID of the parameter.
 * @return Non-NULL pointer to the initialized security parameter.
 */
BSL_Variant_t *BSL_SecOutcome_AppendParam(BSL_SecOutcome_t *self, int64_t param_id);

/** @brief Returns number of parameters in this outcome.
 * @param[in] self This outcome
 * @return Number of parameters
 */
size_t BSL_SecOutcome_CountParams(const BSL_SecOutcome_t *self);

/** Get the security parameter from the security outcome at the provided index
 * @param[in] self security outcome
 * @param[in] param_id The unique ID of the parameter.
 * @param[in] index index to retrieve security parameter from
 * @return Security parameter if found, or NULL pointer.
 */
const BSL_Variant_t *BSL_SecOutcome_GetParam(const BSL_SecOutcome_t *self, int64_t param_id);

/**
 * @return size of security operation
 */
size_t BSL_SecurityAction_Sizeof(void);

/**
 * Initialize security action
 * @param[out] self security action
 */
void BSL_SecurityAction_Init(BSL_SecurityAction_t *self);

/** Initialize from a copy.
 *
 * @param[out] self security action
 * @param[in] src The source of the copy.
 */
void BSL_SecurityAction_InitSet(BSL_SecurityAction_t *self, const BSL_SecurityAction_t *src);

/** Set from a copy.
 */
void BSL_SecurityAction_Set(BSL_SecurityAction_t *self, const BSL_SecurityAction_t *src);

/**
 * De-initialize security action
 * @param[in,out] self security action
 */
void BSL_SecurityAction_Deinit(BSL_SecurityAction_t *self);

/**
 * Add security operation to security action
 * @param[in,out] self action to add security operation to
 * @param[in,out] sec_oper new security operation to add and move from.
 * @return 0 if successful
 */
int BSL_SecurityAction_AppendSecOper(BSL_SecurityAction_t *self, BSL_SecOper_t *sec_oper);

/** Order the Security operations such that execution will be successful
 * @param[in, out] self action to sort
 */
int BSL_SecurityAction_OrderSecOps(BSL_SecurityAction_t *self);

/**
 * @return number of security operation in the @param[in] self action
 */
size_t BSL_SecurityAction_CountSecOpers(const BSL_SecurityAction_t *self);

/**
 * @return the security operation at @param[in] index index in @param[in] self security action
 */
BSL_SecOper_t *BSL_SecurityAction_GetSecOperAtIndex(const BSL_SecurityAction_t *self, size_t index);

/** @brief Increment a security failure for this action set
 *
 * @param[in,out] self Pointer to this security action set.
 */
void BSL_SecurityAction_IncrError(BSL_SecurityAction_t *self);

/** @brief Returns count of failures after processing this action
 *
 * @param[in] self Pointer to this security action.
 * @return Count of errors.
 */
size_t BSL_SecurityAction_CountErrors(const BSL_SecurityAction_t *self);

/** @brief Returns Policy Provider ID of @param[in] self action
 */
uint64_t BSL_SecurityAction_GetPPID(const BSL_SecurityAction_t *self);

/// @brief Returns size of the struct, helpful for dynamic allocation.
/// @return Size of the struct
size_t BSL_SecurityActionSet_Sizeof(void);

/** @brief Initialize a new security action set
 *
 * @param[in,out] self This pre-allocated action set
 */
void BSL_SecurityActionSet_Init(BSL_SecurityActionSet_t *self);

/** Zeroize, clear, and release itself and any owned resources.
 *
 * @param[in,out] self This action set.
 */
void BSL_SecurityActionSet_Deinit(BSL_SecurityActionSet_t *self);

/** @brief Append a security operation to the security action set
 *
 * @param[in,out] self This security action set.
 * @param[in] action Action to include.
 * @return 0 on success, negative on error
 */
int BSL_SecurityActionSet_AppendAction(BSL_SecurityActionSet_t *self, const BSL_SecurityAction_t *action);

/** Return true if internal sanity and consistency checks pass
 *
 * @param[in] self This action set.
 * @return true if action set is consistent
 */
bool BSL_SecurityActionSet_IsConsistent(const BSL_SecurityActionSet_t *self);

/**
 * @return the total number of operations within each of the actions of @param self action set
 */
size_t BSL_SecurityActionSet_CountOperations(const BSL_SecurityActionSet_t *self);

/**
 * @return the total number of invalid actions within @param self action set
 */
size_t BSL_SecurityActionSet_CountInvalidActions(const BSL_SecurityActionSet_t *self);

/** Count number of security operations present in this policy action set.
 *
 * @param[in] self This action set.
 * @return Number of actions, 0 indicates no policy matched.
 */
size_t BSL_SecurityActionSet_CountActions(const BSL_SecurityActionSet_t *self);

/** Returns the Security Operation at the given index.
 *
 * @param[in] self This action set
 * @param[in] index index
 * @return pointer to action at given index, asserting false if not in bound
 */
const BSL_SecurityAction_t *BSL_SecurityActionSet_GetActionAtIndex(const BSL_SecurityActionSet_t *self, size_t index);

/** @brief Returns count of failures after processing this action set
 *
 * @param[in] self Pointer to this security action set.
 * @return Count of errors.
 */
size_t BSL_SecurityActionSet_CountErrors(const BSL_SecurityActionSet_t *self);

/// @brief Returns size of this struct type
size_t BSL_SecurityResponseSet_Sizeof(void);

/** Initialize with the given count of operations and failures
 *
 */
void BSL_SecurityResponseSet_Init(BSL_SecurityResponseSet_t *self);

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

/** Append a result code to the security response set
 * @param[in,out] self the response set to append result to
 * @param[in] result the result code to append
 * @param[in] policy_action the on-failure policy action associated with the response
 */
void BSL_SecurityResponseSet_AppendResult(BSL_SecurityResponseSet_t *self, int64_t result,
                                          BSL_PolicyAction_e policy_action);

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
 * @note Currently the implementation is such that the Policy Provider callback handles the policy action on failure
 * that is stored in the the Security Operations in the Action Set. As such, the backend and Security Context do not use
 * the policy action field of the ::BSL_SecOper_s and the Policy Provider is the sole executor of policy actions
 * regarding failures.
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
                                       BSL_BundleRef_t *bundle, const BSL_SecurityResponseSet_t *response_output);

/// @brief Callback interface to query policy provider to populate the action set
typedef int (*BSL_PolicyInspect_f)(void *user_data, BSL_SecurityActionSet_t *output_action_set,
                                   const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location);

/// @brief Callback interface to finalize policy provider over the action set. Finalize should ignore actions from
/// different policy providers
typedef int (*BSL_PolicyFinalize_f)(void *user_data, const BSL_SecurityActionSet_t *output_action_set,
                                    BSL_BundleRef_t *bundle, const BSL_SecurityResponseSet_t *response_output);

/// @brief Callback interface for policy provider to shut down and release any resources
typedef void (*BSL_PolicyDeinit_f)(void *user_data);

/// @brief Descriptor of opaque data and callbacks for Policy Provider.
struct BSL_PolicyDesc_s
{
    void                *user_data;   ///< Reference to policy provider -specific data
    BSL_PolicyInspect_f  query_fn;    ///< Function pointer to query policy
    BSL_PolicyFinalize_f finalize_fn; ///< Function pointer to finalize policy
    BSL_PolicyDeinit_f   deinit_fn;   ///< Function to deinit the policy provider at termination of BSL context
};

/** Call the underlying security context to perform the given action set
 *
 * @param[in] lib This BSL context
 * @param[out] output_response Pointer to allocated, zeroed memory into which the response is populated
 * @param[in,out] bundle Pointer to bundle, which may be modified.
 * @param[in] action_set Action containing all params and operations.
 * @return 0 on success, negative on failure.
 */
int BSL_SecCtx_ExecutePolicyActionSet(BSL_LibCtx_t *lib, BSL_SecurityResponseSet_t *output_response,
                                      BSL_BundleRef_t *bundle, const BSL_SecurityActionSet_t *action_set);

/** Call the underlying security context to validate the given action set
 *
 * @param[in] lib This BSL context
 * @param[in] bundle Pointer to bundle
 * @param[in] action_set Action containing all params and operations.
 * @return 0 on success, negative on failure.
 */
int BSL_SecCtx_ValidatePolicyActionSet(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                                       const BSL_SecurityActionSet_t *action_set);

/** Signature for Security Context validator for a sec OP.
 *
 * @param[in] lib The library context.
 * @param[in] bundle The bundle to inspect.
 * This is mutable to allow ASB caching.
 * @param[in] sec_oper The security operation to perform.
 * This is mutable to allow marking options as validated.
 * @return True if security operation is deemed valid.
 */
typedef bool (*BSL_SecCtx_Validate_f)(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper);

/** Signature for Security Context executor for a sec OP.
 *
 * @param[in] lib The library context.
 * @param[in,out] bundle The bundle to modify.
 * @param[in] sec_oper The security operation to perform.
 * @param[in] asb For verifier or acceptor, this is the existing ASB structure.
 * @param[in,out] sec_outcome The pre-allocated outcome to populate
 * @return 0 if security operation performed successfully.
 */
typedef int (*BSL_SecCtx_Execute_f)(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                                    BSL_SecOutcome_t *sec_outcome);

/** @brief Security Context descriptor (interface)
 */
struct BSL_SecCtxDesc_s
{
    /// @brief Callback to validate a sec op within a given bundle
    BSL_SecCtx_Validate_f validate;
    /// @brief Callback to execute a sec op within a given bundle
    BSL_SecCtx_Execute_f execute;
};

/** Internal function to execute an operation as source.
 * @warning This is exposed for testing only.
 */
int BSL_ExecBIBSource(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                      BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome);
/** Internal function to execute an operation as verifier or acceptor.
 * @overload
 */
int BSL_ExecBIBVerifierAcceptor(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                                BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome);
/** Internal function to execute an operation as source.
 * @overload
 */
int BSL_ExecBCBSource(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                      BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome);
/** Internal function to execute an operation as verifier or acceptor.
 * @overload
 */
int BSL_ExecBCBVerifierAcceptor(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                                BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_BPSECLIB_PRIVATE_H_ */
