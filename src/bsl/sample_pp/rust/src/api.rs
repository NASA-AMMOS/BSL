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

//! C ABI types owned by the Rust sample policy provider.
//!
//! These definitions are the source of truth for the public sample_pp C
//! header. `cheadergen` reads this module and emits the public declarations;
//! `bindgen` is used only for the C modules that Rust consumes.

use crate::ffi;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_PolicyLocation_e = ffi::BSL_PolicyLocation_e;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_HostEIDPattern_t = ffi::BSL_HostEIDPattern_t;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_HostEID_t = ffi::BSL_HostEID_t;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type m_string_t = ffi::m_string_t;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_SecRole_e = ffi::BSL_SecRole_e;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_SecBlockType_e = ffi::BSL_SecBlockType_e;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSLB_VariantPtrMap_t = ffi::BSLB_VariantPtrMap_t;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_PolicyAction_e = ffi::BSL_PolicyAction_e;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_Variant_t = ffi::BSL_Variant_t;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_SecOper_t = ffi::BSL_SecOper_t;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_BundleRef_t = ffi::BSL_BundleRef_t;

#[allow(non_camel_case_types)]
#[cheadergen::config(skip)]
pub type BSL_SecurityActionSet_t = ffi::BSL_SecurityActionSet_t;

/// Bit-string policy configuration used by `BSLP_PolicyParser_FromBitstringList`.
#[cheadergen::config(export)]
pub type BSLP_PolicyParser_BitstringConfig_t = u32;

/// Opaque policy provider state.
#[cheadergen::config(skip)]
#[repr(C)]
pub struct BSLP_PolicyProvider_t {
    _private: [u8; 0],
}

/// A way to match whether a rule applies to a bundle.
#[cheadergen::config(export)]
#[repr(C)]
pub struct BSLP_PolicyPredicate_t {
    pub location: BSL_PolicyLocation_e,
    pub src_eid_pattern: BSL_HostEIDPattern_t,
    pub secsrc_eid_pattern: BSL_HostEIDPattern_t,
    pub dst_eid_pattern: BSL_HostEIDPattern_t,
}

/// A policy rule containing the metadata and options needed to create a
/// security operation for a matching bundle.
#[cheadergen::config(export)]
#[repr(C)]
pub struct BSLP_PolicyRule_t {
    pub rule_id: i64,
    pub description: m_string_t,
    pub role: BSL_SecRole_e,
    pub target_block_type: u64,
    pub sec_block_type: BSL_SecBlockType_e,
    pub context_id: i64,
    pub options: BSLB_VariantPtrMap_t,
    pub failure_action_code: BSL_PolicyAction_e,
    pub correlation_id: u64,
}
