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
 * Logging implementation for the Mock BPA.
 * This uses the @c stderr output stream in a work thread to ensure thread
 * safety of event sources.
 */
#include "log.h"
#include <BPSecLib_Private.h>
#include <BSLConfig.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <syslog.h>
#include <sys/time.h>
#include <time.h>

#include <m-buffer.h>
#include <m-string.h>
#include <m-atomic.h>

/// Number of events to buffer to I/O thread
#define MOCK_BPA_LOG_QUEUE_SIZE 100

// NOLINTBEGIN
static const char *sev_names[] = {
    NULL,      // LOG_EMERG
    NULL,      // LOG_ALERT
    "CRIT",    // LOG_CRIT
    "ERROR",   // LOG_ERR
    "WARNING", // LOG_WARNING
    NULL,      // LOG_NOTICE
    "INFO",    // LOG_INFO
    "DEBUG",   // LOG_DEBUG
};
// NOLINTEND

/// A single event for the log
typedef struct
{
    /// Source thread ID
    pthread_t thread;
    /// Source event timestamp
    struct timeval timestamp;
    /// Event severity enumeration
    int severity;
    /// File and function context
    string_t context;
    /// Fully formatted message
    string_t message;
} mock_bpa_LogEvent_event_t;

static void mock_bpa_LogEvent_event_init(mock_bpa_LogEvent_event_t *obj)
{
    obj->thread = pthread_self();
    obj->timestamp = (struct timeval){ 0};
    obj->severity = LOG_DEBUG;
    string_init(obj->context);
    string_init(obj->message);
}

static void mock_bpa_LogEvent_event_deinit(mock_bpa_LogEvent_event_t *obj)
{
    string_clear(obj->message);
    string_clear(obj->context);
}

static void mock_bpa_LogEvent_event_init_set(mock_bpa_LogEvent_event_t *obj, const mock_bpa_LogEvent_event_t *src)
{
    obj->thread    = src->thread;
    obj->timestamp = src->timestamp;
    obj->severity  = src->severity;
    string_init_set(obj->context, src->context);
    string_init_set(obj->message, src->message);
}

static void mock_bpa_LogEvent_event_init_move(mock_bpa_LogEvent_event_t *obj, mock_bpa_LogEvent_event_t *src)
{
    obj->thread    = src->thread;
    obj->timestamp = src->timestamp;
    obj->severity  = src->severity;
    string_init_move(obj->context, src->context);
    string_init_move(obj->message, src->message);
}

static void mock_bpa_LogEvent_event_set(mock_bpa_LogEvent_event_t *obj, const mock_bpa_LogEvent_event_t *src)
{
    obj->thread    = src->thread;
    obj->timestamp = src->timestamp;
    obj->severity  = src->severity;
    string_set(obj->context, src->context);
    string_set(obj->message, src->message);
}

/// OPLIST for mock_bpa_LogEvent_event_t
#define M_OPL_mock_bpa_LogEvent_event_t()                                                     \
    (INIT(API_2(mock_bpa_LogEvent_event_init)), INIT_SET(API_6(mock_bpa_LogEvent_event_init_set)), \
     INIT_MOVE(API_6(mock_bpa_LogEvent_event_init_move)), SET(API_6(mock_bpa_LogEvent_event_set)), \
     CLEAR(API_2(mock_bpa_LogEvent_event_deinit)))

// NOLINTBEGIN
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
M_BUFFER_DEF(mock_bpa_LogEvent_queue, mock_bpa_LogEvent_event_t, MOCK_BPA_LOG_QUEUE_SIZE,
             M_BUFFER_THREAD_SAFE | M_BUFFER_BLOCKING | M_BUFFER_PUSH_INIT_POP_MOVE)
// GCOV_EXCL_STOP
/// @endcond

/// Shared least severity
static atomic_int least_severity = LOG_DEBUG;

/// Shared safe queue
static mock_bpa_LogEvent_queue_t event_queue;
/// Sink thread ID
static pthread_t thr_sink;
/// True if ::thr_sink is valid
static atomic_bool thr_valid = ATOMIC_VAR_INIT(false);
// NOLINTEND

// NOLINTBEGIN
static void write_log(const mock_bpa_LogEvent_event_t *event)
{
    ASSERT_ARG_NONNULL(event);

    // already domain validated
    const char *severity_name = sev_names[event->severity];

    char tmbuf[32]; // NOLINT
    {
        time_t    nowtime = event->timestamp.tv_sec;
        struct tm nowtm;
        gmtime_r(&nowtime, &nowtm);

        char  *curs   = tmbuf;
        size_t remain = sizeof(tmbuf) - 1;
        size_t len    = strftime(curs, remain, "%Y-%m-%dT%H:%M:%S", &nowtm);
        curs += len;
        remain -= len;
        snprintf(curs, remain, ".%06ld", event->timestamp.tv_usec);
    }
    char thrbuf[2 * sizeof(pthread_t) + 1];
    {
        const uint8_t *data = (const void *)&(event->thread);
        char          *out  = thrbuf;
        for (size_t ix = 0; ix < sizeof(pthread_t); ++ix)
        {
            sprintf(out, "%02X", *data);
            data++;
            out += 2;
        }
        *out = '\0';
    }
    fprintf(stderr, "%s T:%s <%s> [%s] %s\n", tmbuf, thrbuf, severity_name, string_get_cstr(event->context),
            string_get_cstr(event->message));
    fflush(stderr);
}
// NOLINTEND

static void *work_sink(void *arg _U_)
{
    bool running = true;
    while (running)
    {
        mock_bpa_LogEvent_event_t event;
        mock_bpa_LogEvent_queue_pop(&event, event_queue);
        if (string_empty_p(event.message))
        {
            running = false;
        }
        else
        {
            write_log(&event);
        }
        mock_bpa_LogEvent_event_deinit(&event);
    }
    return NULL;
}

void mock_bpa_LogOpen(void)
{
    mock_bpa_LogEvent_queue_init(event_queue, MOCK_BPA_LOG_QUEUE_SIZE);

    if (pthread_create(&thr_sink, NULL, work_sink, NULL))
    {
        // unsynchronized write
        mock_bpa_LogEvent_event_t manual;
        mock_bpa_LogEvent_event_init(&manual);
        manual.severity = LOG_CRIT;
        string_set_str(manual.message, "mock_bpa_LogOpen() failed");
        write_log(&manual);
        mock_bpa_LogEvent_event_deinit(&manual);
    }
    else
    {
        atomic_store(&thr_valid, true);
    }
}

void mock_bpa_LogClose(void)
{
    // sentinel empty message
    mock_bpa_LogEvent_event_t event;
    mock_bpa_LogEvent_event_init(&event);
    mock_bpa_LogEvent_queue_push(event_queue, event);
    mock_bpa_LogEvent_event_deinit(&event);

    int res = pthread_join(thr_sink, NULL);
    if (res)
    {
        // unsynchronized write
        mock_bpa_LogEvent_event_t manual;
        mock_bpa_LogEvent_event_init(&manual);
        manual.severity = LOG_CRIT;
        string_set_str(manual.message, "mock_bpa_LogClose() failed");
        write_log(&manual);
        mock_bpa_LogEvent_event_deinit(&manual);
    }
    else
    {
        atomic_store(&thr_valid, false);
    }

    // no consumer after join above
    mock_bpa_LogEvent_queue_clear(event_queue);
}

int mock_bpa_LogGetSeverity(int *severity, const char *name)
{
    BSL_CHKERR1(severity);
    BSL_CHKERR1(name);

    for (size_t ix = 0; ix < sizeof(sev_names) / sizeof(const char *); ++ix)
    {
        if (!sev_names[ix])
        {
            continue;
        }
        if (strcasecmp(sev_names[ix], name) == 0)
        {
            *severity = (int)ix;
            return 0;
        }
    }
    return 2;
}

void mock_bpa_LogSetLeastSeverity(int severity)
{
    if ((severity < 0) || (severity > LOG_DEBUG))
    {
        return;
    }

    atomic_store(&least_severity, severity);
}

bool mock_bpa_LogIsEnabledFor(int severity)
{
    const int limit = atomic_load(&least_severity);
    // lower severity has higher define value
    const bool enabled = (limit >= severity);

    return enabled;
}

// NOLINTBEGIN
void mock_bpa_LogEvent(const struct timeval *timestamp, int severity, const char *filename, int lineno, const char *funcname, const char *format, ...)
{
    BSL_CHKVOID(timestamp);

    mock_bpa_LogEvent_event_t event;
    mock_bpa_LogEvent_event_init(&event);
    event.timestamp = *timestamp;
    event.severity = severity;

    if (filename)
    {
        static const char dirsep = '/';

        const char *pos = strrchr(filename, dirsep);
        if (pos)
        {
            pos += 1;
        }
        else
        {
            pos = filename;
        }
        string_printf(event.context, "%s:%d:%s", pos, lineno, funcname);
    }

    {
        va_list val;
        va_start(val, format);
        string_vprintf(event.message, format, val);
        va_end(val);
    }

    // ignore empty messages
    if (!string_empty_p(event.message))
    {
        if (atomic_load(&thr_valid))
        {
            mock_bpa_LogEvent_queue_push(event_queue, event);
        }
        else
        {
            mock_bpa_LogEvent_event_t manual;
            mock_bpa_LogEvent_event_init(&manual);
            manual.severity = LOG_CRIT;
            string_set_str(manual.message, "mock_bpa_LogEvent() called before mock_bpa_openlog()");
            write_log(&manual);
            mock_bpa_LogEvent_event_deinit(&manual);

            write_log(&event);
        }
    }
    mock_bpa_LogEvent_event_deinit(&event);
}
// NOLINTEND
