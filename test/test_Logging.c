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
 */
/** @file
 * @ingroup unit_test
 * Test the BSL logging interface.
 */
#include <bsl/BPSecLib_Private.h>
#include <bsl/BPSecLib_Public.h>
#include <bsl/mock_bpa/agent.h>

#include <pthread.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <unity.h>

typedef struct
{
    bool            called;
    pthread_t       thread;
    struct timespec timestamp;
    int             severity;
    const char     *filename;
    int             lineno;
    const char     *funcname;
} LogCapture_t;

static LogCapture_t capture;

static void capture_log_event(const struct timespec *timestamp, int severity, const char *filename, int lineno,
                              const char *funcname, const char *format, va_list args)
{
    (void)format;
    (void)args;
    capture.called    = true;
    capture.thread    = pthread_self();
    capture.timestamp = *timestamp;
    capture.severity  = severity;
    capture.filename  = filename;
    capture.lineno    = lineno;
    capture.funcname  = funcname;
}

void test_BSL_66(void)
{
    /** BSL_66: logging annotates an entry with time and source-process context. */
    BSL_HostDescriptors_t descriptors = MockBPA_Agent_Descriptors(NULL);
    descriptors.log_event                = capture_log_event;
    TEST_ASSERT_EQUAL_INT(0, BSL_HostDescriptors_Set(descriptors));

    struct timespec before;
    struct timespec after;
    TEST_ASSERT_EQUAL_INT(0, clock_gettime(CLOCK_REALTIME, &before));
    pthread_t caller = pthread_self();
    BSL_LogEvent(LOG_INFO, __FILE__, __LINE__, __func__, "BSL_66 logging metadata");
    TEST_ASSERT_EQUAL_INT(0, clock_gettime(CLOCK_REALTIME, &after));

    TEST_ASSERT_TRUE(capture.called);
    TEST_ASSERT_TRUE(pthread_equal(caller, capture.thread));
    TEST_ASSERT_EQUAL_INT(LOG_INFO, capture.severity);
    TEST_ASSERT_NOT_NULL(capture.filename);
    TEST_ASSERT_NOT_NULL(capture.funcname);
    TEST_ASSERT_EQUAL_STRING(__func__, capture.funcname);
    TEST_ASSERT_TRUE(capture.lineno > 0);
    TEST_ASSERT_TRUE(capture.timestamp.tv_sec >= before.tv_sec);
    TEST_ASSERT_TRUE(capture.timestamp.tv_sec <= after.tv_sec);
    TEST_ASSERT_TRUE(capture.timestamp.tv_nsec >= 0);
    TEST_ASSERT_TRUE(capture.timestamp.tv_nsec < 1000000000L);
    TEST_ASSERT_TRUE(capture.timestamp.tv_sec > 0);
}
