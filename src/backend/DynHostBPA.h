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
/** @file
 * Private interface for the dynamic BPA context.
 * @ingroup backend_dyn
 */
#ifndef BSL_BPA_DYN_H_
#define BSL_BPA_DYN_H_

#include <HostBPA.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Dynamic BPA descriptor.
 */
typedef struct
{
    /// User data pointer for callbacks
    void *user_data;

    /// Callback for BSL_HostEID_Init()
    int (*eid_init)(BSL_HostEID_t *eid, void *user_data);
    /// Callback for BSL_HostEID_Deinit()
    void (*eid_deinit)(BSL_HostEID_t *eid, void *user_data);
    /// Callback for BSL_Host_GetSecSrcEID()
    int (*get_secsrc)(BSL_HostEID_t *eid, void *user_data);

    /// @brief Callback for BSL_HostEID_EncodeToCBOR()
    int (*eid_to_cbor)(void *encoder, const BSL_HostEID_t *eid);
    
    /// @brief Callback for BSL_HostEID_DecodeFromCBOR
    int (*eid_from_cbor)(void *encoder, BSL_HostEID_t *eid);

    /// Callback for BSL_HostEID_DecodeFromText()
    int (*eid_from_text)(BSL_HostEID_t *eid, const char *text, void *user_data);
    /// Callback for BSL_HostEID_EncodeToText()
    int (*eid_to_text)(string_t out, const BSL_HostEID_t *eid, void *user_data);

    /// Callback for BSL_HostEIDPattern_Init()
    int (*eidpat_init)(BSL_HostEIDPattern_t *pat, void *user_data);
    /// Callback for BSL_HostEIDPattern_Deinit()
    void (*eidpat_deinit)(BSL_HostEIDPattern_t *pat, void *user_data);
    /// Callback for BSL_HostEIDPattern_DecodeFromText()
    int (*eidpat_from_text)(BSL_HostEIDPattern_t *pat, const char *text, void *user_data);
    /// Callback for BSL_HostEIDPattern_IsMatch()
    bool (*eidpat_match)(const BSL_HostEIDPattern_t *pat, const BSL_HostEID_t *eid, void *user_data);

    /// Callback for BSL_HostLabel_Init()
    int (*label_init)(BSL_HostLabel_t *label, void *user_data);
    /// Callback for BSL_HostLabel_Init()
    void (*label_deinit)(BSL_HostLabel_t *label, void *user_data);
    /// Callback for BSL_HostLabel_DecodeFromText()
    int (*label_from_text)(BSL_HostLabel_t *label, const char *text, void *user_data);
    /// Callback for BSL_HostLabel_EncodeToText()
    int (*label_to_text)(string_t out, const BSL_HostLabel_t *label, void *user_data);

} BSL_HostDescriptors_t;

/** Set the BPA descriptor for this process.
 *
 * @param desc The descriptor to use for future BPA functions.
 * @return Zero if successful.
 */
int BSL_HostDescriptors_Set(BSL_HostDescriptors_t desc);

/** Copy the BPA descriptor for this process.
 * @param[out] desc The descriptor to copy into.
 */
void BSL_HostDescriptors_Get(BSL_HostDescriptors_t *desc);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_BPA_DYN_H_
