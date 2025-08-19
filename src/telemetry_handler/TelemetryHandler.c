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

/**
 * @file
 * @brief Local implementation of locally-defined data structures.
 * @ingroup tlm_handler
 */
#include <stddef.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <pthread.h>

#include <BPSecLib_Private.h>

#include "TelemetryHandler.h"


typedef struct {
    atomic_uint_least64_t success;
    atomic_uint_least64_t fail;
} BSLT_InternalCounters_t;

static BSLT_InternalCounters_t tlm_counters;
static pthread_once_t tlm_once = PTHREAD_ONCE_INIT;


static void BSLT_TelemetryCounters_Init_Once(void) {

    atomic_init(&tlm_counters.success, 0u);
    atomic_init(&tlm_counters.fail, 0u);
}

static inline void BSLT_TelemetryCounters_Check_Init(void) {

    (void)pthread_once(&tlm_once, BSLT_TelemetryCounters_Init_Once);
}

void BSLT_ResetTelemetryCounters(void) {

    BSLT_TelemetryCounters_Check_Init();

    atomic_store_explicit(&tlm_counters.success, 0u, memory_order_release);
    atomic_store_explicit(&tlm_counters.fail, 0u, memory_order_release);
}

size_t BSLT_RetrieveTelemetryCount(BSL_TelemetryType_e counter_type) {

    BSLT_TelemetryCounters_Check_Init();

    size_t val;

    if (counter_type == BSL_TELEMETRY_FAIL) {
        val = atomic_load_explicit(&tlm_counters.fail, memory_order_acquire);
    }
    else {
        val = atomic_load_explicit(&tlm_counters.success, memory_order_acquire);
    }

    return val;
}

void BSLT_IncrementTelemetryCount(BSL_TelemetryType_e counter_type) {

    BSLT_TelemetryCounters_Check_Init();

    if (counter_type == BSL_TELEMETRY_FAIL) {
        atomic_fetch_add_explicit(&tlm_counters.fail, 1u, memory_order_relaxed);
    }
    else {
        atomic_fetch_add_explicit(&tlm_counters.success, 1u, memory_order_relaxed);
    }
}
