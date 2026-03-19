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
 * @ingroup mock_bpa
 * Logging interface for the Mock BPA.
 */

#ifndef BSL_MOCK_BPA_LOG_H_
#define BSL_MOCK_BPA_LOG_H_

#include <stdbool.h>
#include <sys/time.h>

/** Opens the event log.
 * @note This should be called once per process, not thread or library instance.
 * At the end of the process there should be a call to BSL_closelog()
 *
 * This is a mimic to POSIX @c openlog()
 */
void mock_bpa_LogOpen(void);

/** Closes the event log.
 * This is a mimic to POSIX @c closelog()
 */
void mock_bpa_LogClose(void);

/** Interpret a text name as a severity level.
 *
 * @param[out] severity The associated severity level.
 * @param[in] name The text name, which is case insensitive.
 * @return Zero if successful.
 */
int mock_bpa_LogGetSeverity(int *severity, const char *name);

/** Set the least severity enabled for logging.
 * Other events will be dropped by the logging facility.
 * This function is multi-thread safe.
 *
 * @param severity The severity from a subset of the POSIX syslog values.
 */
void mock_bpa_LogSetLeastSeverity(int severity);

/// Interface for BSL_HostDescriptors_t::log_is_enabled_for
bool mock_bpa_LogIsEnabledFor(int severity);
/// Interface for BSL_HostDescriptors_t::log_event
void mock_bpa_LogEvent(const struct timeval *timestamp, int severity, const char *filename, int lineno, const char *funcname, const char *format, ...);

#endif /* BSL_MOCK_BPA_LOG_H_ */
