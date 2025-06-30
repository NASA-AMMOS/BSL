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
#include "encode_primary.h"
#include "Logging.h"
#include "util.h"
#include <inttypes.h>
#include <qcbor/qcbor_encode.h>
#include <unity.h>

void test_encoding(void)
{
    BSL_BundlePrimaryBlock_t prim_blk_info = { .version       = 7,
                                               .flags         = 0,
                                               .crc_type      = 0,
                                               .dest_eid      = NULL,
                                               .src_node_id   = NULL,
                                               .report_to_eid = NULL,
                                               .timestamp     = { .bundle_creation_time = 1000, .seq_num = 1001 },
                                               .lifetime      = 0 };

    UsefulBufC crc_buf = { NULL, 0 }; // TODO dummy crc
    UsefulBufC encoded;
    uint8_t    prim_blk_encoded[1000];
    UsefulBuf  buf = { prim_blk_encoded, 1000 };
    bsl_bundle_ctx_prim_blk_encode(&prim_blk_info, buf, crc_buf, &encoded);
    const void *encoded_prim    = encoded.ptr;
    size_t      encoded_prim_sz = encoded.len;

    TEST_ASSERT_EQUAL(33, encoded_prim_sz);

    UsefulBufC actual = { encoded_prim, encoded_prim_sz };
    // clang-format off
    uint8_t exp[] = {   0x88, 
                            0x07, 
                            0x00, 
                            0x00, 
                            0x82, 
                                0x01, 
                                0x64, 
                                    0x74, 0x65, 0x73, 0x74,
                            0x82, 
                                0x01, 
                                0x64, 
                                    0x74, 0x65, 0x73, 0x74,
                            0x82, 
                                0x01, 
                                0x64, 
                                    0x74, 0x65, 0x73, 0x74,
                            0x82,
                                0x19, 0x03, 0xe8,
                                0x19, 0x03, 0xe9,
                            0x00          
                    };
    // clang-format on
    TEST_ASSERT_EQUAL_MEMORY(exp, actual.ptr, sizeof(exp));
}
