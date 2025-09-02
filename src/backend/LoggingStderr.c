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
 * Implementation of event logging using @c stderr output stream.
 * @ingroup backend_dyn
 */
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>

#include <BPSecLib_Private.h>
#include <BSLConfig.h>

#include <m-buffer.h>
#include <m-string.h>
#include <m-atomic.h>

/// Number of events to buffer to I/O thread
#define BSL_LOG_QUEUE_SIZE 100

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
} BSL_LogEvent_event_t;

static void BSL_LogEvent_event_init(BSL_LogEvent_event_t *obj)
{
    obj->thread = pthread_self();
    gettimeofday(&(obj->timestamp), NULL);
    obj->severity = LOG_DEBUG;
    string_init(obj->context);
    string_init(obj->message);
}

static void BSL_LogEvent_event_deinit(BSL_LogEvent_event_t *obj)
{
    string_clear(obj->message);
    string_clear(obj->context);
}

static void BSL_LogEvent_event_init_set(BSL_LogEvent_event_t *obj, const BSL_LogEvent_event_t *src)
{
    obj->thread    = src->thread;
    obj->timestamp = src->timestamp;
    obj->severity  = src->severity;
    string_init_set(obj->context, src->context);
    string_init_set(obj->message, src->message);
}

static void BSL_LogEvent_event_init_move(BSL_LogEvent_event_t *obj, BSL_LogEvent_event_t *src)
{
    obj->thread    = src->thread;
    obj->timestamp = src->timestamp;
    obj->severity  = src->severity;
    string_init_move(obj->context, src->context);
    string_init_move(obj->message, src->message);
}

static void BSL_LogEvent_event_set(BSL_LogEvent_event_t *obj, const BSL_LogEvent_event_t *src)
{
    obj->thread    = src->thread;
    obj->timestamp = src->timestamp;
    obj->severity  = src->severity;
    string_set(obj->context, src->context);
    string_set(obj->message, src->message);
}

/// OPLIST for BSL_LogEvent_event_t
#define M_OPL_BSL_LogEvent_event_t()                                                     \
    (INIT(API_2(BSL_LogEvent_event_init)), INIT_SET(API_6(BSL_LogEvent_event_init_set)), \
     INIT_MOVE(API_6(BSL_LogEvent_event_init_move)), SET(API_6(BSL_LogEvent_event_set)), \
     CLEAR(API_2(BSL_LogEvent_event_deinit)))

// NOLINTBEGIN
/// @cond Doxygen_Suppress
M_BUFFER_DEF(BSL_LogEvent_queue, BSL_LogEvent_event_t, BSL_LOG_QUEUE_SIZE,
             M_BUFFER_THREAD_SAFE | M_BUFFER_BLOCKING | M_BUFFER_PUSH_INIT_POP_MOVE)
/// @endcond

/// Shared least severity
static atomic_int least_severity = LOG_DEBUG;

/// Shared safe queue
static BSL_LogEvent_queue_t event_queue;
/// Sink thread ID
static pthread_t thr_sink;
/// True if ::thr_sink is valid
static atomic_bool thr_valid = ATOMIC_VAR_INIT(false);
// NOLINTEND

char *BSL_Log_DumpAsHexString(char *dstbuf, size_t dstlen, const uint8_t *srcbuf, size_t srclen)
{
    ASSERT_ARG_NONNULL(dstbuf);
    ASSERT_ARG_NONNULL(srcbuf);
    ASSERT_ARG_EXPR(dstlen > 0);
    ASSERT_ARG_EXPR(srclen > 0);

    memset(dstbuf, 0, dstlen);
    const char hex_digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < srclen && (((i * 2) + 1) < dstlen - 1); i++)
    {
        dstbuf[(i * 2)]     = hex_digits[(srcbuf[i] >> 4) & 0x0F];
        dstbuf[(i * 2) + 1] = hex_digits[srcbuf[i] & 0x0F];
    }
    return dstbuf;
}

// NOLINTBEGIN
static void write_log(const BSL_LogEvent_event_t *event)
{
    ASSERT_ARG_NONNULL(event);

    // already domain validated
    const char *prioname = sev_names[event->severity];

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
    fprintf(stderr, "%s T:%s <%s> [%s] %s\n", tmbuf, thrbuf, prioname, string_get_cstr(event->context),
            string_get_cstr(event->message));
    fflush(stderr);
}
// NOLINTEND

static void *work_sink(void *arg _U_)
{
    bool running = true;
    while (running)
    {
        BSL_LogEvent_event_t event;
        BSL_LogEvent_queue_pop(&event, event_queue);
        if (string_empty_p(event.message))
        {
            running = false;
        }
        else
        {
            write_log(&event);
        }
        BSL_LogEvent_event_deinit(&event);
    }
    return NULL;
}

void BSL_openlog(void)
{
    BSL_LogEvent_queue_init(event_queue, BSL_LOG_QUEUE_SIZE);

    if (pthread_create(&thr_sink, NULL, work_sink, NULL))
    {
        // unsynchronized write
        BSL_LogEvent_event_t manual;
        BSL_LogEvent_event_init(&manual);
        manual.severity = LOG_CRIT;
        string_set_str(manual.message, "BSL_openlog() failed");
        write_log(&manual);
        BSL_LogEvent_event_deinit(&manual);
    }
    else
    {
        atomic_store(&thr_valid, true);
    }
}

void BSL_closelog(void)
{
    // sentinel empty message
    BSL_LogEvent_event_t event;
    BSL_LogEvent_event_init(&event);
    BSL_LogEvent_queue_push(event_queue, event);
    BSL_LogEvent_event_deinit(&event);

    int res = pthread_join(thr_sink, NULL);
    if (res)
    {
        // unsynchronized write
        BSL_LogEvent_event_t manual;
        BSL_LogEvent_event_init(&manual);
        manual.severity = LOG_CRIT;
        string_set_str(manual.message, "BSL_closelog() failed");
        write_log(&manual);
        BSL_LogEvent_event_deinit(&manual);
    }
    else
    {
        atomic_store(&thr_valid, false);
    }

    // no consumer after join above
    BSL_LogEvent_queue_clear(event_queue);
}

int BSL_LogGetSeverity(int *severity, const char *name)
{
    CHKERR1(severity)
    CHKERR1(name)

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

void BSL_LogSetLeastSeverity(int severity)
{
    if ((severity < 0) || (severity > LOG_DEBUG))
    {
        return;
    }

    atomic_store(&least_severity, severity);
}

bool BSL_LogIsEnabledFor(int severity)
{
    if ((severity < 0) || (severity > LOG_DEBUG))
    {
        return false;
    }

    const int limit = atomic_load(&least_severity);
    // lower severity has higher define value
    const bool enabled = (limit >= severity);

    return enabled;
}

// NOLINTBEGIN
void BSL_LogEvent(int severity, const char *filename, int lineno, const char *funcname, const char *format, ...)
{
    if (!BSL_LogIsEnabledFor(severity))
    {
        return;
    }

    BSL_LogEvent_event_t event;
    BSL_LogEvent_event_init(&event);
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
            BSL_LogEvent_queue_push(event_queue, event);
        }
        else
        {
            BSL_LogEvent_event_t manual;
            BSL_LogEvent_event_init(&manual);
            manual.severity = LOG_CRIT;
            string_set_str(manual.message, "BSL_LogEvent() called before BSL_openlog()");
            write_log(&manual);
            BSL_LogEvent_event_deinit(&manual);

            write_log(&event);
        }
    }
    BSL_LogEvent_event_deinit(&event);
}
// NOLINTEND
