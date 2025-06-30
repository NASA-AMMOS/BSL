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
#include "bpa_types.h"
#include "bsl_ctx_dyn.h"
#include "bundle_ctx_dyn.h"
#include "Logging.h"
#include "util.h"
#include <inttypes.h>
#include <qcbor/qcbor_encode.h>

/**
 * Encode primary block to a CBOR bytestring
 * @param[in] prim_blk primary block information to be encoded
 * @param[in,out] buf buffer to hold encoded result.
 * @param[in] crc buffer holding encoded CBOR encoded CRC data
 * @param[out] out pointer to buffer containing pointer and size of resulting encoded bytestr
 * @returns 0 if successful
 */
int bsl_bundle_ctx_prim_blk_encode(const BSL_BundlePrimaryBlock_t *prim_blk, UsefulBuf buf, UsefulBufC crc,
                                   UsefulBufC *out);
