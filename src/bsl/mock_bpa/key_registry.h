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
 */

#ifndef BSL_MOCK_BPA_KEY_REGISTRY_H_
#define BSL_MOCK_BPA_KEY_REGISTRY_H_

#include <inttypes.h>

#include <bsl/crypto/KeyStore.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Get key store descriptors for the process.
 *
 * @return Populated descriptor struct.
 */
BSL_KeyStore_Descriptors_t MockBPA_KeyStore_Descriptors(void);

void MockBPA_KeyStore_Init(void);
void MockBPA_KeyStore_Deinit(void);

/** Erase key entry from crypto library registry, if present.
 *  @param[in] keyid key ID of key to remove.
 * @return Zero if the key was present.
 */
int MockBPA_KeyStore_RemoveKey(const BSL_Data_t *keyid);

/**
 * Add a new key to the crypto key registry
 * @param[in] keyid key ID that crypto functions will use to access key
 * @param[out] handle Key handle to add to the registry.
 * Once the key is added it should be treated as read-only for thread-safety purposes.
 * When handle is output, the handle must be released with BSL_Crypto_ReleaseKeyHandle() when it is done being used.
 * @return Zero upon success.
 */
int MockBPA_KeyStore_AddKey(const BSL_Data_t *keyid, BSL_Crypto_KeyHandle_t handle);

/** Add a context-specific parameter to a known key.
 *
 * @param[in] handle The key ID to update.
 * @param[in] param_id The parameter to access.
 * If the parameter does not already exist it will be created.
 * @return Non-NULL pointer if successful.
 */
BSL_IdValPair_t *MockBPA_KeyStore_SetKeyParameter(BSL_Crypto_KeyHandle_t handle, int64_t param_id);

/** @brief Initialize keys
 * @param[in] file_path path to JSON file with JWKs or CBOR file with @c COSE_KeySet
 * @return 0 if successful.
 */
int mock_bpa_key_registry_init(const char *file_path);

/** @warning Exposed only for testing.
 * @param infd The file descriptor to read from.
 */
int mock_bpa_key_registry_init_jwk(int infd);

/** @warning Exposed only for testing.
 * @param infd The file descriptor to read from.
 */
int mock_bpa_key_registry_init_cosekey(int infd);

/**
 * Custom RNG function for BCB testing
 */
int mock_bpa_rfc9173_bcb_cek(unsigned char *buf, int len);

#ifdef __cplusplus
} // extern C
#endif

#endif
