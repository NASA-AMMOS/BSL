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
 * Abstract interface for event logging.
 * @ingroup frontend
 */
/** @page Logging
 * The BSL provides a general purpose thread-safe logging facility
 * for the library itself and users of the library.
 *
 * Logging must be initialized once per process using BSL_openlog() and
 * should be de-initialized before exiting the process using BSL_closelog().
 * Log events themselves are queued by using one of the severity-specific
 * macros listed below.
 *
 * The supported log severity values are a subset of the POSIX syslog values
 * with enumerations and descriptions repeated below.
 *
 *  * @c LOG_CRIT critical conditions, logged by ::BSL_LOG_CRIT
 *  * @c LOG_ERR error conditions, logged by ::BSL_LOG_ERR
 *  * @c LOG_WARNING warning conditions, logged by ::BSL_LOG_WARNING
 *  * @c LOG_INFO informational message, logged by ::BSL_LOG_INFO
 *  * @c LOG_DEBUG debug-level message, logged by ::BSL_LOG_DEBUG
 */
#ifndef BSL_LOGGING_H_
#define BSL_LOGGING_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <syslog.h>

/**
 * Helper function to print the ASCII encoding of a given bytestream to a given target buffer.
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

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_LOGGING_H_ */
