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
 * @ingroup backend_dyn
 * Implementation of the host BPA and its callback functions.
 */
#include <Logging.h>
#include <TypeDefintions.h>

#include "DynHostBPA.h"

static BSL_HostDescriptors_t _bpa = { .user_data = NULL };

int BSL_HostDescriptors_Set(BSL_HostDescriptors_t desc)
{
    CHKERR1(desc.eid_init);
    CHKERR1(desc.eid_deinit);
    CHKERR1(desc.eid_from_cbor);
    CHKERR1(desc.get_secsrc);
    CHKERR1(desc.eid_from_text);
    CHKERR1(desc.eid_to_text);

    CHKERR1(desc.eidpat_init);
    CHKERR1(desc.eidpat_deinit);
    CHKERR1(desc.eidpat_from_text);
    CHKERR1(desc.eidpat_match);

    CHKERR1(desc.label_init);
    CHKERR1(desc.label_deinit);
    CHKERR1(desc.label_from_text);
    CHKERR1(desc.label_to_text);

    _bpa = desc;
    return 0;
}

void BSL_HostDescriptors_Get(BSL_HostDescriptors_t *desc)
{
    CHKVOID(desc);
    *desc = _bpa;
}

int BSL_HostEID_Init(BSL_HostEID_t *eid)
{
    CHKERR1(_bpa.eid_init);
    return _bpa.eid_init(eid, _bpa.user_data);
}

void BSL_HostEID_Deinit(BSL_HostEID_t *eid)
{
    CHKVOID(_bpa.eid_deinit);
    _bpa.eid_deinit(eid, _bpa.user_data);
}

int BSL_Host_GetSecSrcEID(BSL_HostEID_t *eid)
{
    CHKERR1(_bpa.get_secsrc);
    return _bpa.get_secsrc(eid, _bpa.user_data);
}

int BSL_HostEID_EncodeToCBOR(const BSL_HostEID_t *eid, void *user_data)
{
    CHKERR1(_bpa.get_secsrc);
    return _bpa.eid_to_cbor(user_data, eid);
}

int BSL_HostEID_DecodeFromCBOR(BSL_HostEID_t *eid, void *decoder)
{
    assert(eid != NULL);
    assert(eid->handle != NULL);
    assert(decoder != NULL);
    int ecode = _bpa.eid_from_cbor(decoder, eid);
    assert(eid->handle != NULL);
    return ecode;
}

int BSL_HostEID_DecodeFromText(BSL_HostEID_t *eid, const char *text)
{
    CHKERR1(_bpa.eid_from_text);
    return _bpa.eid_from_text(eid, text, _bpa.user_data);
}

int BSL_HostEID_EncodeToText(string_t out, const BSL_HostEID_t *eid)
{
    CHKERR1(_bpa.eid_to_text);
    return _bpa.eid_to_text(out, eid, _bpa.user_data);
}

int BSL_HostEIDPattern_Init(BSL_HostEIDPattern_t *pat)
{
    CHKERR1(_bpa.eidpat_init);
    return _bpa.eidpat_init(pat, _bpa.user_data);
}

void BSL_HostEIDPattern_Deinit(BSL_HostEIDPattern_t *pat)
{
    CHKVOID(_bpa.eidpat_deinit);
    _bpa.eidpat_deinit(pat, _bpa.user_data);
}

int BSL_HostEIDPattern_DecodeFromText(BSL_HostEIDPattern_t *pat, const char *text)
{
    CHKERR1(_bpa.eidpat_from_text);
    return _bpa.eidpat_from_text(pat, text, _bpa.user_data);
}

bool BSL_HostEIDPattern_IsMatch(const BSL_HostEIDPattern_t *pat, const BSL_HostEID_t *eid)
{
    CHKERR1(_bpa.eidpat_match);
    return _bpa.eidpat_match(pat, eid, _bpa.user_data);
}

int BSL_HostLabel_Init(BSL_HostLabel_t *label)
{
    CHKERR1(_bpa.label_init);
    return _bpa.label_init(label, _bpa.user_data);
}

void BSL_HostLabel_Deinit(BSL_HostLabel_t *label)
{
    CHKVOID(_bpa.label_deinit);
    _bpa.label_deinit(label, _bpa.user_data);
}

int BSL_HostLabel_DecodeFromText(BSL_HostLabel_t *label, const char *text)
{
    CHKERR1(_bpa.label_from_text);
    return _bpa.label_from_text(label, text, _bpa.user_data);
}

int BSL_HostLabel_EncodeToText(string_t out, const BSL_HostLabel_t *label)
{
    CHKERR1(_bpa.label_to_text);
    return _bpa.label_to_text(out, label, _bpa.user_data);
}
