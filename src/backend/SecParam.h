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
 * @file SecParam.h
 * @ingroup backend_dyn
 * @brief Defines the RFC 9172 Security Parameter of the Abstract Security Block
 *
 * @details
 *
 * The details from the RFC are as follows:
 *
 * <blockquote>
 * This field captures one or more security context parameters that should be used
 * when processing the security service described by this security block. This field
 * SHALL be represented by a CBOR array. Each entry in this array is a single security
 * context parameter. A single parameter SHALL also be represented as a CBOR array
 * comprising a 2-tuple of the Id and value of the parameter, as follows.
 *
 * **Parameter Id:**
 *  * This field identifies which parameter is being specified.
 *  * This field SHALL be represented as a CBOR unsigned integer.
 *  * Parameter Ids are selected as described in Section 3.10.
 *
 * **Parameter Value:**
 *  * This field captures the value associated with this parameter.
 *  * This field SHALL be represented by the applicable CBOR representation of the parameter, in accordance with
 * Section 3.10.
 *
 * </blockquote>
 *
 * @cite  https://www.rfc-editor.org/rfc/rfc9172.html#section-3.6-3.10.1
 *
 * @author Bill.Van.Besien@jhuapl.edu
 */
/** @file
 * @brief Implementation of a RFC9172 Parameter
 * @ingroup backend_dyn
 */
#ifndef BSLB_SECPARAM_H_
#define BSLB_SECPARAM_H_

#include <stdint.h>

#include <m-list.h>

#include <BPSecLib_Private.h>

struct BSL_SecParam_s
{
    /// @brief Parameter ID
    uint64_t param_id;

    /// @brief Private. Indicates whether this is an integer or bytestring.
    enum BSL_SecParam_Types_e _type;

    /// @brief Private. When an integer, this field is populated with the correct value.
    uint64_t _uint_value;

    /// @brief Private. When a bytestring, this field is set, with the _bytelen set accordingly.
    uint8_t _bytes[BSL_DEFAULT_BYTESTR_LEN + 1];

    /// @brief Private. When a bytestring, this field is the length of param, and always less than
    /// BSL_DEFAULT_BYTESTR_LEN.
    size_t _bytelen;
};

// NOLINTBEGIN
/**
 * Defines a MLib basic list of Security Parameters.
 */
LIST_DEF(BSLB_SecParamList, BSL_SecParam_t, M_POD_OPLIST)
// NOLINTEND

#endif /* BSLB_SECPARAM_H_ */
