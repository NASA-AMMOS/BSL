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
 * Declarations for Agent initialization.
 * @ingroup mock_bpa
 */
#ifndef BSL_MOCK_BPA_AGENT_H_
#define BSL_MOCK_BPA_AGENT_H_

#include "ctr.h"
#include "policy_registry.h"

#include <BPSecLib_Public.h>
#include <BPSecLib_Private.h>
#include <policy_provider/SamplePolicyProvider.h>

#include <m-atomic.h>
#include <m-buffer.h>
#include <m-string.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

int MockBPA_GetBundleMetadata(const BSL_BundleRef_t *bundle_ref, BSL_PrimaryBlock_t *result_primary_block);
int MockBPA_GetBlockNums(const BSL_BundleRef_t *bundle_ref, size_t block_id_array_capacity,
                         uint64_t *block_id_array_result, size_t *result_count);
int MockBPA_GetBlockMetadata(const BSL_BundleRef_t *bundle_ref, uint64_t block_num,
                             BSL_CanonicalBlock_t *result_canonical_block);
int MockBPA_ReallocBTSD(BSL_BundleRef_t *bundle_ref, uint64_t block_num, size_t bytesize);
int MockBPA_CreateBlock(BSL_BundleRef_t *bundle_ref, uint64_t block_type_code, uint64_t *result_block_num);
int MockBPA_RemoveBlock(BSL_BundleRef_t *bundle_ref, uint64_t block_num);
int MockBPA_DeleteBundle(BSL_BundleRef_t *bundle_ref);

/// Queue size for bundle queues
#define MOCKBPA_DATA_QUEUE_SIZE 100

/**
 * @struct MockBPA_data_queue_t
 * @brief Container for a thread-safe circular queue of ::mock_bpa_ctr_t
 * @cite lib:mlib.
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
M_BUFFER_DEF(MockBPA_data_queue, mock_bpa_ctr_t, MOCKBPA_DATA_QUEUE_SIZE,
             BUFFER_QUEUE | BUFFER_THREAD_SAFE | BUFFER_PUSH_INIT_POP_MOVE | BUFFER_BLOCKING)
/// @endcond
// NOLINTEND

/** Overall Mock BPA state above any particular bundle handling.
 */
typedef struct MockBPA_Agent_s
{
    /** Shared operating state.
     * Set to @c false while running, and @c true to stop.
     */
    atomic_bool stop_state;

    /// Bundles received from the application
    MockBPA_data_queue_t over_rx;
    /// Bundles delivered to the application
    MockBPA_data_queue_t over_tx;
    /// Bundles received from the CL
    MockBPA_data_queue_t under_rx;
    /// Bundles forwarded to the CL
    MockBPA_data_queue_t under_tx;
    /// Bundles in need of delivery
    MockBPA_data_queue_t deliver;
    /// Bundles in need of forwarding
    MockBPA_data_queue_t forward;

    /** Worker threads.
     * These are valid between ::MockBPA_Agent_Start() and ::MockBPA_Agent_Join().
     */
    pthread_t thr_over_rx, thr_under_rx, thr_deliver, thr_forward;

    /// Pipe end for notifying TX worker
    int tx_notify_w;
    /// Pipe end for TX worker
    int tx_notify_r;

    /// Policy provider for ::BSL_POLICYLOCATION_APPIN
    BSLP_PolicyProvider_t *policy_appin;
    /// Policy provider for ::BSL_POLICYLOCATION_APPOUT
    BSLP_PolicyProvider_t *policy_appout;
    /// Policy provider for ::BSL_POLICYLOCATION_CLIN
    BSLP_PolicyProvider_t *policy_clin;
    /// Policy provider for ::BSL_POLICYLOCATION_CLOUT
    BSLP_PolicyProvider_t *policy_clout;

    /// BSL context for ::BSL_POLICYLOCATION_APPIN
    BSL_LibCtx_t *bsl_appin;
    /// BSL context for ::BSL_POLICYLOCATION_APPOUT
    BSL_LibCtx_t *bsl_appout;
    /// BSL context for ::BSL_POLICYLOCATION_CLIN
    BSL_LibCtx_t *bsl_clin;
    /// BSL context for ::BSL_POLICYLOCATION_CLOUT
    BSL_LibCtx_t *bsl_clout;
    /// Mutex for aggregating telemetry on all above ::BSL_LibCtx_t instances
    pthread_mutex_t tlm_mutex;

    /// Configuration for local app-facing address
    struct sockaddr_in over_addr;
    /// Configuration for application-side address
    struct sockaddr_in app_addr;
    /// Configuration for local CL-facing address
    struct sockaddr_in under_addr;
    /// Configuration for CL-side address
    struct sockaddr_in router_addr;

} MockBPA_Agent_t;

/** Get host descriptors without a specific agent.
 *
 * @param[in] agent The agent to associate as user data.
 */
BSL_HostDescriptors_t MockBPA_Agent_Descriptors(MockBPA_Agent_t *agent);

/** Initialize and register this mock BPA for the current process.
 *
 * @param[out] agent The agent to initialize.
 * @return Zero if successful.
 */
int MockBPA_Agent_Init(MockBPA_Agent_t *agent);

/** Clean up the mock BPA for the current process.
 *
 * @param[out] agent The agent to deinitialize.
 */
void MockBPA_Agent_Deinit(MockBPA_Agent_t *agent);

/** Start worker threads.
 *
 * @param[out] agent The agent to start threads for.
 * @return Zero if successful.
 * @sa MockBPA_Agent_Join()
 */
int MockBPA_Agent_Start(MockBPA_Agent_t *agent);

/** Stop an agent from another thread or a signal handler.
 *
 * @param[in,out] agent The agent to set the stopping state on.
 */
void MockBPA_Agent_Stop(MockBPA_Agent_t *agent);

/** Execute the main thread activity while work threads are running.
 * This will block until MockBPA_Agent_Stop() is called.
 *
 * @param[out] agent The agent to work for.
 * @return Zero if successful.
 */
int MockBPA_Agent_Exec(MockBPA_Agent_t *agent);

/** Wait for and join worker threads.
 *
 * @param[out] agent The agent to start threads for.
 * @return Zero if successful.
 * @sa MockBPA_Agent_Start()
 */
int MockBPA_Agent_Join(MockBPA_Agent_t *agent);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_AGENT_H_
