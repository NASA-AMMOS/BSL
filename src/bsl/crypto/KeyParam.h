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
 * @ingroup cose_sc
 * Header for COSE message structures @cite rfc9052.
 */

#ifndef BSL_CRYPTO_KEYPARAM_H
#define BSL_CRYPTO_KEYPARAM_H

#ifdef __cplusplus
extern "C" {
#endif

/** Key parameter code points managed by IANA.
 * https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 * Symmetric key k (-1) is handled specially in this API version of BSL.
 */
enum BSL_Crypto_KeyParam_e
{
    /** Key type value as @c int64_t.
     * Values supported are in ::BSL_Crypto_KeyParam_Type_e
     */
    BSL_CRYPTO_KEYPARAM_KTY = 1,
    /// Key ID value as bytes
    BSL_CRYPTO_KEYPARAM_KID = 2,
    /// Algorithm value as @c int64_t
    BSL_CRYPTO_KEYPARAM_ALG = 3,
    /// Base IV value as bytes
    BSL_CRYPTO_KEYPARAM_BASEIV = 5,
    /// Curve as @c int64_t
    BSL_CRYPTO_KEYPARAM_EC2_CRV = -1,
    /// EC2 public X as bytes
    BSL_CRYPTO_KEYPARAM_EC2_X = -2,
    /// EC2 public Y as bytes
    BSL_CRYPTO_KEYPARAM_EC2_Y = -3,
    /// EC2 private D as bytes
    BSL_CRYPTO_KEYPARAM_EC2_D = -4,
    /// AKP public key as bytes
    BSL_CRYPTO_KEYPARAM_AKP_PUB = -1,
    /// AKP private key as bytes
    BSL_CRYPTO_KEYPARAM_AKP_PRIV = -2,
};

/** Relevant key types managed by IANA.
 * https://www.iana.org/assignments/cose#key-type
 */
enum BSL_Crypto_KeyParam_Type_e
{
    /// EC2 key type
    BSL_CRYPTO_KEYPARAM_TYPE_EC2 = 2,
    /// Symmetric key type
    BSL_CRYPTO_KEYPARAM_TYPE_SYMMETRIC = 4,
    /// Algorithm-key pair type
    BSL_CRYPTO_KEYPARAM_TYPE_AKP = 7,
};

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_CRYPTO_KEYPARAM_H */
