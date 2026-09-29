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

use crate::ffi;
use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::ptr;

pub type BslResult<T = ()> = Result<T, c_int>;

pub fn ok() -> c_int {
    ffi::BSL_SUCCESS as c_int
}

pub fn result_to_c_int(result: BslResult) -> c_int {
    match result {
        Ok(()) => ok(),
        Err(err) => err,
    }
}

pub fn check_success(err: c_int) -> BslResult {
    if err == ok() {
        Ok(())
    } else {
        Err(err)
    }
}

pub fn check_success_as(err: c_int, mapped_err: c_int) -> BslResult {
    if err == ok() {
        Ok(())
    } else {
        Err(mapped_err)
    }
}

pub fn bsl_err<T>(err: c_int) -> BslResult<T> {
    Err(err)
}

pub fn arg_null_err<T>() -> BslResult<T> {
    bsl_err(ffi::BSL_ERR_ARG_NULL as c_int)
}

pub fn failure_err<T>() -> BslResult<T> {
    bsl_err(ffi::BSL_ERR_FAILURE as c_int)
}

pub fn host_callback_err<T>() -> BslResult<T> {
    bsl_err(ffi::BSL_ERR_HOST_CALLBACK_FAILED as c_int)
}

pub fn policy_config_err<T>() -> BslResult<T> {
    bsl_err(ffi::BSL_ERR_POLICY_CONFIG as c_int)
}

pub fn policy_failed_err<T>() -> BslResult<T> {
    bsl_err(ffi::BSL_ERR_POLICY_FAILED as c_int)
}

pub fn policy_query_err<T>() -> BslResult<T> {
    bsl_err(ffi::BSL_ERR_POLICY_QUERY as c_int)
}

pub fn property_check_err<T>() -> BslResult<T> {
    bsl_err(ffi::BSL_ERR_PROPERTY_CHECK_FAILED as c_int)
}

pub fn security_context_err<T>() -> BslResult<T> {
    bsl_err(ffi::BSL_ERR_SECURITY_CONTEXT_FAILED as c_int)
}

pub fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        unsafe { Some(CStr::from_ptr(ptr).to_string_lossy().into_owned()) }
    }
}

pub fn make_cstring(text: &str) -> BslResult<CString> {
    CString::new(text).map_err(|_| ffi::BSL_ERR_POLICY_CONFIG as c_int)
}

pub fn parse_i64_text(text: &str) -> BslResult<i64> {
    let trimmed_start = text.trim_start();
    if trimmed_start.is_empty() {
        return policy_config_err();
    }

    let (sign, rest) = match trimmed_start.as_bytes()[0] {
        b'+' => (1_i128, &trimmed_start[1..]),
        b'-' => (-1_i128, &trimmed_start[1..]),
        _ => (1_i128, trimmed_start),
    };

    if rest.is_empty() || rest.chars().any(char::is_whitespace) {
        return policy_config_err();
    }

    let (radix, digits) = if rest.starts_with("0x") || rest.starts_with("0X") {
        (16_u32, &rest[2..])
    } else {
        (10_u32, rest)
    };

    if digits.is_empty() {
        return policy_config_err();
    }

    let value = i128::from_str_radix(digits, radix).map_err(|_| ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    let signed = sign * value;
    if signed < i64::MIN as i128 || signed > i64::MAX as i128 {
        return policy_config_err();
    }
    Ok(signed as i64)
}

pub fn parse_i64_value(value: &serde_json::Value) -> BslResult<i64> {
    if let Some(number) = value.as_i64() {
        Ok(number)
    } else if let Some(text) = value.as_str() {
        parse_i64_text(text)
    } else {
        policy_config_err()
    }
}

pub fn parse_u64_value(value: &serde_json::Value) -> BslResult<u64> {
    let int_value = parse_i64_value(value)?;
    if int_value < 0 {
        policy_config_err()
    } else {
        Ok(int_value as u64)
    }
}

pub fn parse_boolish(value: &serde_json::Value) -> BslResult<bool> {
    if let Some(value) = value.as_bool() {
        Ok(value)
    } else if let Some(number) = value.as_i64() {
        Ok(number != 0)
    } else if let Some(text) = value.as_str() {
        Ok(text != "0")
    } else {
        policy_config_err()
    }
}

pub fn decode_hex(text: &str) -> BslResult<Vec<u8>> {
    let hex = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);

    if hex.len() % 2 != 0 {
        return policy_config_err();
    }

    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        let high = hex_val(pair[0])?;
        let low = hex_val(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_val(ch: u8) -> BslResult<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => policy_config_err(),
    }
}

pub unsafe fn set_variant_text(option: *mut ffi::BSL_Variant_t, text: &str) -> BslResult {
    if option.is_null() {
        return arg_null_err();
    }
    let c_text = make_cstring(text)?;
    ffi::BSL_Variant_SetTextstr(option, c_text.as_ptr());
    Ok(())
}

pub unsafe fn set_variant_int(option: *mut ffi::BSL_Variant_t, value: i64) -> BslResult {
    if option.is_null() {
        return arg_null_err();
    }
    ffi::BSL_Variant_SetInt64(option, value);
    Ok(())
}

pub unsafe fn set_variant_bytes(option: *mut ffi::BSL_Variant_t, bytes: &[u8]) -> BslResult {
    if option.is_null() {
        return arg_null_err();
    }

    let mut data = std::mem::MaybeUninit::<ffi::BSL_Data_t>::zeroed().assume_init();
    let ptr = if bytes.is_empty() { ptr::null() } else { bytes.as_ptr() };
    ffi::BSLP_Rust_Data_InitViewConst(&mut data, ptr, bytes.len());
    ffi::BSL_Variant_SetBytestr(option, data);
    Ok(())
}

pub fn role_from_text(text: &str) -> BslResult<ffi::BSL_SecRole_e> {
    match text {
        "s" | "source" => Ok(ffi::BSL_SECROLE_SOURCE),
        "v" | "verifier" => Ok(ffi::BSL_SECROLE_VERIFIER),
        "a" | "acceptor" => Ok(ffi::BSL_SECROLE_ACCEPTOR),
        _ => policy_config_err(),
    }
}

pub fn location_from_text(text: &str) -> BslResult<ffi::BSL_PolicyLocation_e> {
    match text {
        "appin" => Ok(ffi::BSL_POLICYLOCATION_APPIN),
        "appout" => Ok(ffi::BSL_POLICYLOCATION_APPOUT),
        "clin" => Ok(ffi::BSL_POLICYLOCATION_CLIN),
        "clout" => Ok(ffi::BSL_POLICYLOCATION_CLOUT),
        _ => policy_config_err(),
    }
}

pub fn failure_action_from_text(text: &str) -> BslResult<ffi::BSL_PolicyAction_e> {
    match text {
        "delete_bundle" => Ok(ffi::BSL_POLICYACTION_DROP_BUNDLE),
        "drop_block" => Ok(ffi::BSL_POLICYACTION_DROP_BLOCK),
        "nothing" => Ok(ffi::BSL_POLICYACTION_NOTHING),
        _ => policy_config_err(),
    }
}

pub fn service_from_text(text: &str) -> BslResult<ffi::BSL_SecBlockType_e> {
    match text {
        "bib" | "bib-integrity" => Ok(ffi::BSL_SECBLOCKTYPE_BIB),
        "bcb" | "bcb-confidentiality" => Ok(ffi::BSL_SECBLOCKTYPE_BCB),
        _ => policy_config_err(),
    }
}
