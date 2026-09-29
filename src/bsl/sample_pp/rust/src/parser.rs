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

use crate::api;
use crate::ffi;
use crate::provider;
use crate::provider::{init_predicate_from_rust, init_rule_from_rust, move_options_into_rule};
use crate::util::{
    cstr_to_string, decode_hex, failure_action_from_text, location_from_text, ok, parse_boolish, parse_i64_text,
    parse_i64_value, parse_u64_value, policy_config_err, role_from_text, service_from_text, set_variant_bytes,
    set_variant_int, set_variant_text, BslResult,
};
use libc::c_int;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::mem::{self, MaybeUninit};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::ptr;

struct TempOptions {
    ptr: *mut ffi::BSLP_RustVariantMap_t,
}

impl TempOptions {
    unsafe fn new() -> BslResult<Self> {
        let ptr = ffi::BSLP_Rust_VariantMap_New();
        if ptr.is_null() {
            Err(ffi::BSL_ERR_FAILURE as c_int)
        } else {
            Ok(Self { ptr })
        }
    }

    fn as_ptr(&self) -> *mut ffi::BSLP_RustVariantMap_t {
        self.ptr
    }
}

impl Drop for TempOptions {
    fn drop(&mut self) {
        unsafe {
            ffi::BSLP_Rust_VariantMap_Destroy(self.ptr);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CorrelationSpec {
    context_id: i64,
    sec_block_type: ffi::BSL_SecBlockType_e,
}

fn value_object<'a>(value: &'a Value) -> BslResult<&'a Map<String, Value>> {
    value.as_object().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)
}

fn member<'a>(object: &'a Map<String, Value>, key: &str) -> BslResult<&'a Value> {
    object.get(key).ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)
}

fn member_str<'a>(object: &'a Map<String, Value>, key: &str) -> BslResult<&'a str> {
    member(object, key)?
        .as_str()
        .ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)
}

unsafe fn option_add_or_erase(
    options: &TempOptions,
    opt_id: i64,
    value: &Value,
) -> BslResult<Option<*mut ffi::BSL_Variant_t>> {
    if value.is_null() {
        ffi::BSLP_Rust_VariantMap_Erase(options.as_ptr(), opt_id);
        Ok(None)
    } else {
        let option = ffi::BSLP_Rust_VariantMap_Add(options.as_ptr(), opt_id);
        if option.is_null() {
            Err(ffi::BSL_ERR_FAILURE as c_int)
        } else {
            Ok(Some(option))
        }
    }
}

unsafe fn option_text(options: &TempOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    let text = value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    set_variant_text(option, text)
}

unsafe fn option_int(options: &TempOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    set_variant_int(option, parse_i64_value(value)?)
}

unsafe fn option_bool(options: &TempOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    set_variant_int(option, if parse_boolish(value)? { 1 } else { 0 })
}

unsafe fn option_hex_bytes(options: &TempOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    let text = value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    let bytes = decode_hex(text)?;
    set_variant_bytes(option, &bytes)
}

unsafe fn option_text_as_bytes(options: &TempOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    let text = value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    set_variant_bytes(option, text.as_bytes())
}

unsafe fn option_cose_aad_scope(options: &TempOptions, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, ffi::BSLX_COSESC_OPTION_AAD_SCOPE as i64, value)? else {
        return Ok(());
    };

    let object = value_object(value)?;
    let mut items = Vec::<ffi::BSLX_CoseSc_AadScope_Item_t>::with_capacity(object.len());
    for (key, flags_value) in object.iter() {
        items.push(ffi::BSLX_CoseSc_AadScope_Item_t {
            key: parse_i64_text(key)?,
            flags: parse_i64_value(flags_value)?,
        });
    }

    let ptr = if items.is_empty() { ptr::null() } else { items.as_ptr() };
    let err = ffi::BSLX_CoseSc_SetAadScope(option, ptr, items.len());
    if err == ok() {
        Ok(())
    } else {
        Err(err)
    }
}

unsafe fn parse_sc1_option(options: &TempOptions, key: &str, value: &Value) -> BslResult {
    match key {
        "key_name" => option_text(options, ffi::BSLX_BIB_OPT_KEY_ID as i64, value),
        "sha_variant" => option_int(options, ffi::BSLX_BIB_OPT_SHA_VARIANT as i64, value),
        "scope_flags" => option_int(options, ffi::BSLX_BIB_OPT_SCOPE as i64, value),
        "key_wrap" => option_bool(options, ffi::BSLX_BIB_OPT_USE_KEY_WRAP as i64, value),
        _ => policy_config_err(),
    }
}

unsafe fn parse_sc2_option(options: &TempOptions, key: &str, value: &Value) -> BslResult {
    match key {
        "key_name" => option_text(options, ffi::BSLX_BCB_OPT_KEY_ID as i64, value),
        "aes_variant" => option_int(options, ffi::BSLX_BCB_OPT_AES_VARIANT as i64, value),
        "aad_scope" => option_int(options, ffi::BSLX_BCB_OPT_SCOPE as i64, value),
        "key_wrap" => option_bool(options, ffi::BSLX_BCB_OPT_USE_KEY_WRAP as i64, value),
        _ => policy_config_err(),
    }
}

unsafe fn parse_sc3_option(options: &TempOptions, key: &str, value: &Value) -> BslResult {
    if key == "key_name" {
        return option_text_as_bytes(options, ffi::BSLX_COSESC_OPTION_KEY_ID as i64, value);
    }

    if key.eq_ignore_ascii_case("key_id") {
        option_hex_bytes(options, ffi::BSLX_COSESC_OPTION_KEY_ID as i64, value)
    } else if key.eq_ignore_ascii_case("target_alg") {
        option_int(options, ffi::BSLX_COSESC_OPTION_TGT_ALG as i64, value)
    } else if key.eq_ignore_ascii_case("aad_scope") {
        option_cose_aad_scope(options, value)
    } else if key.eq_ignore_ascii_case("iv_base") {
        option_hex_bytes(options, ffi::BSLX_COSESC_OPTION_IV_BASE as i64, value)
    } else if key.eq_ignore_ascii_case("iv_counter_offset") {
        option_int(options, ffi::BSLX_COSESC_OPTION_IV_COUNTER_OFFSET as i64, value)
    } else if key.eq_ignore_ascii_case("salt_length") {
        option_int(options, ffi::BSLX_COSESC_OPTION_SALT_LENGTH as i64, value)
    } else if key.eq_ignore_ascii_case("salt_base") {
        option_hex_bytes(options, ffi::BSLX_COSESC_OPTION_SALT_BASE as i64, value)
    } else if key.eq_ignore_ascii_case("salt_counter_offset") {
        option_int(options, ffi::BSLX_COSESC_OPTION_SALT_COUNTER_OFFSET as i64, value)
    } else {
        policy_config_err()
    }
}

unsafe fn parse_option(options: &TempOptions, context_id: i64, key: &str, value: &Value) -> BslResult {
    if context_id == ffi::RFC9173_CONTEXTID_BIB_HMAC_SHA2 as i64 {
        parse_sc1_option(options, key, value)
    } else if context_id == ffi::RFC9173_CONTEXTID_BCB_AES_GCM as i64 {
        parse_sc2_option(options, key, value)
    } else if context_id == ffi::BSLX_COSESC_CTX_ID as i64 {
        parse_sc3_option(options, key, value)
    } else {
        policy_config_err()
    }
}

unsafe fn parse_sc_parms(options: &TempOptions, context_id: i64, value: &Value) -> BslResult {
    if let Some(object) = value.as_object() {
        for (key, entry_value) in object.iter() {
            parse_option(options, context_id, key, entry_value)?;
        }
        Ok(())
    } else if let Some(array) = value.as_array() {
        for entry in array.iter() {
            let entry_object = value_object(entry)?;
            let key = member_str(entry_object, "id")?;
            let entry_value = member(entry_object, "value")?;
            parse_option(options, context_id, key, entry_value)?;
        }
        Ok(())
    } else {
        policy_config_err()
    }
}

unsafe fn parse_one_rule(
    rule_set_item: &Value,
    policy: *mut api::BSLP_PolicyProvider_t,
    correlations: &mut HashMap<u64, CorrelationSpec>,
) -> BslResult {
    let item_object = value_object(rule_set_item)?;
    let policy_rule = value_object(member(item_object, "policyrule")?)?;
    let filter = value_object(member(policy_rule, "filter")?)?;
    let spec = value_object(member(policy_rule, "spec")?)?;

    let rule_id = parse_i64_value(member(filter, "rule_id")?)?;
    let description = policy_rule.get("desc").and_then(Value::as_str);
    let role = role_from_text(member_str(filter, "role")?)?;
    let src = filter.get("src").map_or(Ok("*:**"), |value| value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int))?;
    let dst = filter
        .get("dest")
        .map_or(Ok("*:**"), |value| value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int))?;
    let secsrc = filter
        .get("sec_src")
        .map_or(Ok("*:**"), |value| value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int))?;
    let target_block_type = parse_u64_value(member(filter, "tgt")?)?;
    let location = location_from_text(member_str(filter, "loc")?)?;

    let failure_action = match policy_rule.get("policy_action_on_fail") {
        Some(value) => failure_action_from_text(value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?)?,
        None => ffi::BSL_POLICYACTION_NOTHING,
    };

    let correlation = match policy_rule.get("correlation") {
        Some(value) => parse_u64_value(value)?,
        None => 0,
    };
    if policy_rule.contains_key("correlation") && correlation == 0 {
        return policy_config_err();
    }

    let sec_block_type = service_from_text(member_str(spec, "svc")?)?;
    let context_id = parse_i64_value(member(spec, "sc_id")?)?;
    if context_id != ffi::RFC9173_CONTEXTID_BIB_HMAC_SHA2 as i64
        && context_id != ffi::RFC9173_CONTEXTID_BCB_AES_GCM as i64
        && context_id != ffi::BSLX_COSESC_CTX_ID as i64
    {
        return policy_config_err();
    }

    if correlation > 0 {
        let spec = CorrelationSpec {
            context_id,
            sec_block_type,
        };
        if let Some(prev) = correlations.get(&correlation) {
            if *prev != spec {
                return Err(ffi::BSL_ERR_CORRELATION_MISMATCH as c_int);
            }
        } else {
            correlations.insert(correlation, spec);
        }
    }

    let options = TempOptions::new()?;
    parse_sc_parms(&options, context_id, member(spec, "sc_parms")?)?;

    let mut predicate = MaybeUninit::<api::BSLP_PolicyPredicate_t>::zeroed().assume_init();
    let mut rule = MaybeUninit::<api::BSLP_PolicyRule_t>::zeroed().assume_init();
    let mut predicate_initialized = false;
    let mut rule_initialized = false;

    let result = (|| -> BslResult {
        init_predicate_from_rust(&mut predicate, location, src, secsrc, dst)?;
        predicate_initialized = true;
        init_rule_from_rust(
            &mut rule,
            rule_id,
            description,
            context_id,
            role,
            sec_block_type,
            target_block_type,
            failure_action,
        )?;
        rule_initialized = true;

        if correlation > 0 {
            let err = provider::BSLP_PolicyRule_SetCorrelation(&mut rule, correlation);
            if err != ok() {
                return Err(err);
            }
        }

        let err = move_options_into_rule(&mut rule, options.as_ptr());
        if err != ok() {
            return Err(err);
        }

        let err = provider::BSLP_PolicyProvider_AddRule(policy, &mut rule, &mut predicate);
        if err != ok() {
            return Err(err);
        }
        rule_initialized = false;
        predicate_initialized = false;
        Ok(())
    })();

    if rule_initialized {
        provider::BSLP_PolicyRule_Deinit(&mut rule);
    }
    if predicate_initialized {
        provider::BSLP_PolicyPredicate_Deinit(&mut predicate);
    }

    result
}

unsafe fn parse_no_rule_actions(root: &Map<String, Value>, policy: *mut api::BSLP_PolicyProvider_t) -> BslResult {
    let Some(no_rules) = root.get("policy_action_no_rules") else {
        return Ok(());
    };
    let object = value_object(no_rules)?;
    for (key, value) in object.iter() {
        let location = location_from_text(key)?;
        let action = failure_action_from_text(value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?)?;
        if action == ffi::BSL_POLICYACTION_DROP_BLOCK {
            return policy_config_err();
        }
        provider::BSLP_PolicyProvider_SetNoRuleAction(policy, location, action);
    }
    Ok(())
}

fn validate_event_set(root: &Map<String, Value>) -> BslResult {
    let Some(event_set) = root.get("event_set") else {
        return Ok(());
    };
    let Some(event_object) = event_set.as_object() else {
        return Ok(());
    };

    for (_key, events) in event_object.iter() {
        let Some(array) = events.as_array() else {
            continue;
        };
        for event in array.iter() {
            let event = value_object(event)?;
            member_str(event, "event_id")?;
            if let Some(actions) = event.get("actions") {
                let actions = actions.as_array().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
                for action in actions.iter() {
                    if action.as_str().is_none() {
                        return policy_config_err();
                    }
                }
            }
        }
    }
    Ok(())
}

unsafe fn parse_root_text(text: &str, policy: *mut api::BSLP_PolicyProvider_t) -> c_int {
    if policy.is_null() {
        return ffi::BSL_ERR_ARG_NULL as c_int;
    }

    let root: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return ffi::BSL_ERR_POLICY_CONFIG as c_int,
    };
    let root_object = match root.as_object() {
        Some(object) => object,
        None => return ffi::BSL_ERR_POLICY_CONFIG as c_int,
    };

    if validate_event_set(root_object).is_err() {
        return ffi::BSL_ERR_POLICY_CONFIG as c_int;
    }

    if parse_no_rule_actions(root_object, policy).is_err() {
        return ffi::BSL_ERR_POLICY_CONFIG as c_int;
    }

    let Some(rules) = root_object.get("policyrule_set").and_then(Value::as_array) else {
        return ffi::BSL_ERR_POLICY_CONFIG as c_int;
    };

    let mut correlations = HashMap::<u64, CorrelationSpec>::new();
    let mut failures = 0usize;
    for rule in rules.iter() {
        if parse_one_rule(rule, policy, &mut correlations).is_err() {
            failures += 1;
        }
    }

    if failures == 0 {
        ok()
    } else {
        ffi::BSL_ERR_POLICY_CONFIG as c_int
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyParser_LoadFile(
    file_path: *const libc::c_char,
    policy: *mut api::BSLP_PolicyProvider_t,
) -> c_int {
    if file_path.is_null() || policy.is_null() {
        return ffi::BSL_ERR_ARG_NULL as c_int;
    }

    let path = Path::new(std::ffi::OsStr::from_bytes(CStr::from_ptr(file_path).to_bytes()));
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return ffi::BSL_ERR_FAILURE as c_int,
    };

    let mut text = String::new();
    if file.read_to_string(&mut text).is_err() {
        return ffi::BSL_ERR_POLICY_CONFIG as c_int;
    }
    parse_root_text(&text, policy)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyParser_LoadFd(
    infd: c_int,
    policy: *mut api::BSLP_PolicyProvider_t,
) -> c_int {
    if policy.is_null() {
        return ffi::BSL_ERR_ARG_NULL as c_int;
    }

    let dup_fd = libc::dup(infd);
    if dup_fd < 0 {
        return ffi::BSL_ERR_FAILURE as c_int;
    }
    let mut file = File::from_raw_fd(dup_fd);
    let mut text = String::new();
    if file.read_to_string(&mut text).is_err() {
        return ffi::BSL_ERR_POLICY_CONFIG as c_int;
    }
    parse_root_text(&text, policy)
}

unsafe fn add_bitstring_option_text(
    options: &TempOptions,
    opt_id: i64,
    text: &str,
) -> BslResult {
    let option = ffi::BSLP_Rust_VariantMap_Add(options.as_ptr(), opt_id);
    if option.is_null() {
        return Err(ffi::BSL_ERR_FAILURE as c_int);
    }
    set_variant_text(option, text)
}

unsafe fn add_bitstring_option_int(options: &TempOptions, opt_id: i64, value: i64) -> BslResult {
    let option = ffi::BSLP_Rust_VariantMap_Add(options.as_ptr(), opt_id);
    if option.is_null() {
        return Err(ffi::BSL_ERR_FAILURE as c_int);
    }
    set_variant_int(option, value)
}

unsafe fn register_policy_from_bitstring(policy_bits: u64, policy: *mut api::BSLP_PolicyProvider_t) -> BslResult {
    const BSLP_BITSTR_BUNDLE_BLOCK_TYPE_PRIMARY: u64 = 0;
    const BSLP_BITSTR_BUNDLE_BLOCK_TYPE_PAYLOAD: u64 = 1;
    const BSLP_BITSTR_BUNDLE_BLOCK_TYPE_BLOCK_192: u64 = 2;
    const BSLP_BITSTR_BUNDLE_BLOCK_TYPE_BUNDLE_AGE: u64 = 3;

    let sec_block_type = policy_bits & 0x01;
    let policy_loc = (policy_bits >> 1) & 0x01;
    let bundle_block_type = (policy_bits >> 2) & 0x03;
    let policy_action_type = (policy_bits >> 4) & 0x03;
    let sec_role = (policy_bits >> 6) & 0x03;
    let use_wrapped_key = (policy_bits >> 8) & 0x01;
    let policy_ignore = (policy_bits >> 9) & 0x01;

    let options = TempOptions::new()?;
    let (sec_block_enum, context_id) = if sec_block_type == 1 {
        add_bitstring_option_int(
            &options,
            ffi::BSLX_BCB_OPT_SCOPE as i64,
            ffi::RFC9173_BCB_AADSCOPEFLAGID_INC_NONE as i64,
        )?;
        add_bitstring_option_int(
            &options,
            ffi::BSLX_BCB_OPT_AES_VARIANT as i64,
            ffi::RFC9173_BCB_AES_VARIANT_A128GCM as i64,
        )?;
        if use_wrapped_key == 1 {
            add_bitstring_option_text(&options, ffi::BSLX_BCB_OPT_KEY_ID as i64, "9103")?;
            add_bitstring_option_int(&options, ffi::BSLX_BCB_OPT_USE_KEY_WRAP as i64, 1)?;
        } else {
            add_bitstring_option_text(&options, ffi::BSLX_BCB_OPT_KEY_ID as i64, "9102")?;
            add_bitstring_option_int(&options, ffi::BSLX_BCB_OPT_USE_KEY_WRAP as i64, 0)?;
        }
        (ffi::BSL_SECBLOCKTYPE_BCB, ffi::RFC9173_CONTEXTID_BCB_AES_GCM as i64)
    } else {
        add_bitstring_option_int(&options, ffi::BSLX_BIB_OPT_SCOPE as i64, 0)?;
        add_bitstring_option_int(
            &options,
            ffi::BSLX_BIB_OPT_SHA_VARIANT as i64,
            ffi::RFC9173_BIB_SHA_HMAC512 as i64,
        )?;
        add_bitstring_option_text(&options, ffi::BSLX_BIB_OPT_KEY_ID as i64, "9100")?;
        add_bitstring_option_int(&options, ffi::BSLX_BIB_OPT_USE_KEY_WRAP as i64, 0)?;
        (ffi::BSL_SECBLOCKTYPE_BIB, ffi::RFC9173_CONTEXTID_BIB_HMAC_SHA2 as i64)
    };

    let location = if policy_loc == 1 {
        ffi::BSL_POLICYLOCATION_CLIN
    } else {
        ffi::BSL_POLICYLOCATION_CLOUT
    };

    let target_block_type = match bundle_block_type {
        BSLP_BITSTR_BUNDLE_BLOCK_TYPE_PRIMARY => ffi::BSL_BLOCK_TYPE_PRIMARY as u64,
        BSLP_BITSTR_BUNDLE_BLOCK_TYPE_PAYLOAD => ffi::BSL_BLOCK_TYPE_PAYLOAD as u64,
        BSLP_BITSTR_BUNDLE_BLOCK_TYPE_BLOCK_192 => 192,
        BSLP_BITSTR_BUNDLE_BLOCK_TYPE_BUNDLE_AGE => ffi::BSL_BLOCK_TYPE_BUNDLE_AGE as u64,
        _ => ffi::BSL_BLOCK_TYPE_PRIMARY as u64,
    };

    let failure_action = match policy_action_type {
        0 => ffi::BSL_POLICYACTION_NOTHING,
        1 => ffi::BSL_POLICYACTION_DROP_BLOCK,
        2 => ffi::BSL_POLICYACTION_DROP_BUNDLE,
        _ => ffi::BSL_POLICYACTION_NOTHING,
    };

    let role = match sec_role {
        0 => ffi::BSL_SECROLE_SOURCE,
        1 => ffi::BSL_SECROLE_VERIFIER,
        2 => ffi::BSL_SECROLE_ACCEPTOR,
        _ => ffi::BSL_SECROLE_VERIFIER,
    };

    let src_pat = if policy_ignore == 1 { "" } else { "*:**" };
    let description = format!("Policy: {:x}", policy_bits);

    let mut predicate = MaybeUninit::<api::BSLP_PolicyPredicate_t>::zeroed().assume_init();
    let mut rule = MaybeUninit::<api::BSLP_PolicyRule_t>::zeroed().assume_init();
    let mut predicate_initialized = false;
    let mut rule_initialized = false;

    let result = (|| -> BslResult {
        init_predicate_from_rust(&mut predicate, location, src_pat, "*:**", "*:**")?;
        predicate_initialized = true;
        init_rule_from_rust(
            &mut rule,
            0,
            Some(&description),
            context_id,
            role,
            sec_block_enum,
            target_block_type,
            failure_action,
        )?;
        rule_initialized = true;
        let err = move_options_into_rule(&mut rule, options.as_ptr());
        if err != ok() {
            return Err(err);
        }
        let err = provider::BSLP_PolicyProvider_AddRule(policy, &mut rule, &mut predicate);
        if err != ok() {
            return Err(err);
        }
        rule_initialized = false;
        predicate_initialized = false;
        Ok(())
    })();

    if rule_initialized {
        provider::BSLP_PolicyRule_Deinit(&mut rule);
    }
    if predicate_initialized {
        provider::BSLP_PolicyPredicate_Deinit(&mut predicate);
    }
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyParser_FromBitstringList(
    policies: *const libc::c_char,
    policy: *mut api::BSLP_PolicyProvider_t,
) -> c_int {
    if policies.is_null() || policy.is_null() {
        return ffi::BSL_ERR_ARG_NULL as c_int;
    }

    let Some(policy_text) = cstr_to_string(policies) else {
        return ffi::BSL_ERR_ARG_NULL as c_int;
    };

    for token in policy_text.split(',') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(bits) = parse_i64_text(trimmed) else {
            continue;
        };
        if bits < 0 || bits > i32::MAX as i64 {
            continue;
        }
        let _ = register_policy_from_bitstring(bits as u64, policy);
    }
    ok()
}
