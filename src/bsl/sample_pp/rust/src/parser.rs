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
    add_policy_option, arg_null_err, check_success, cstr_to_string, decode_hex, failure_action_from_text,
    location_from_text, parse_boolish, parse_i64_text, parse_i64_value, parse_u64_value, policy_config_err,
    result_to_c_int, role_from_text, service_from_text, BslResult, OwnedVariant, PolicyOptions,
};
use libc::c_int;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::ptr;

fn default_eid_pattern() -> String {
    "*:**".to_owned()
}

#[derive(Deserialize)]
struct PolicyDocument {
    policyrule_set: Vec<Value>,
}

#[derive(Deserialize)]
struct RuleSetItemJson {
    policyrule: PolicyRuleJson,
}

#[derive(Deserialize)]
struct PolicyRuleJson {
    filter: RuleFilterJson,
    spec: RuleSpecJson,
}

#[derive(Deserialize)]
struct RuleFilterJson {
    rule_id: Value,
    role: String,

    #[serde(default = "default_eid_pattern")]
    src: String,

    #[serde(rename = "dest", default = "default_eid_pattern")]
    dst: String,

    #[serde(rename = "sec_src", default = "default_eid_pattern")]
    secsrc: String,

    tgt: Value,
    loc: String,
}

#[derive(Deserialize)]
struct RuleSpecJson {
    svc: String,
    sc_id: Value,
    sc_parms: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecurityContext {
    BibHmacSha2,
    BcbAesGcm,
    Cose,
}

impl SecurityContext {
    fn from_context_id(context_id: i64) -> BslResult<Self> {
        match context_id {
            id if id == ffi::RFC9173_CONTEXTID_BIB_HMAC_SHA2 as i64 => Ok(Self::BibHmacSha2),
            id if id == ffi::RFC9173_CONTEXTID_BCB_AES_GCM as i64 => Ok(Self::BcbAesGcm),
            id if id == ffi::BSLX_COSESC_CTX_ID as i64 => Ok(Self::Cose),
            _ => policy_config_err(),
        }
    }

    unsafe fn parse_option(self, options: &mut PolicyOptions, key: &str, value: &Value) -> BslResult {
        match self {
            Self::BibHmacSha2 => parse_bib_option(options, key, value),
            Self::BcbAesGcm => parse_bcb_option(options, key, value),
            Self::Cose => parse_cose_option(options, key, value),
        }
    }

    unsafe fn parse_object(self, options: &mut PolicyOptions, object: &Map<String, Value>) -> BslResult {
        if self == Self::Cose {
            return parse_cose_object(options, object);
        }

        for (key, entry_value) in object {
            self.parse_option(options, key, entry_value)?;
        }
        Ok(())
    }
}

struct StagedPredicate {
    inner: api::BSLP_PolicyPredicate_t,
    initialized: bool,
}

impl StagedPredicate {
    unsafe fn new(
        location: api::BSL_PolicyLocation_e,
        src: &str,
        secsrc: &str,
        dst: &str,
    ) -> BslResult<Self> {
        let mut inner = MaybeUninit::<api::BSLP_PolicyPredicate_t>::zeroed().assume_init();
        init_predicate_from_rust(&mut inner, location, src, secsrc, dst)?;
        Ok(Self {
            inner,
            initialized: true,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut api::BSLP_PolicyPredicate_t {
        &mut self.inner
    }

    fn disarm(&mut self) {
        self.initialized = false;
    }
}

impl Drop for StagedPredicate {
    fn drop(&mut self) {
        unsafe {
            if self.initialized {
                provider::BSLP_PolicyPredicate_Deinit(&mut self.inner);
            }
        }
    }
}

struct StagedRule {
    inner: api::BSLP_PolicyRule_t,
    initialized: bool,
}

impl StagedRule {
    unsafe fn new(
        rule_id: i64,
        description: Option<&str>,
        context_id: i64,
        role: api::BSL_SecRole_e,
        sec_block_type: api::BSL_SecBlockType_e,
        target_block_type: u64,
        failure_action_code: api::BSL_PolicyAction_e,
    ) -> BslResult<Self> {
        let mut inner = MaybeUninit::<api::BSLP_PolicyRule_t>::zeroed().assume_init();
        init_rule_from_rust(
            &mut inner,
            rule_id,
            description,
            context_id,
            role,
            sec_block_type,
            target_block_type,
            failure_action_code,
        )?;
        Ok(Self {
            inner,
            initialized: true,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut api::BSLP_PolicyRule_t {
        &mut self.inner
    }

    fn disarm(&mut self) {
        self.initialized = false;
    }
}

impl Drop for StagedRule {
    fn drop(&mut self) {
        unsafe {
            if self.initialized {
                provider::BSLP_PolicyRule_Deinit(&mut self.inner);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CorrelationSpec {
    context_id: i64,
    sec_block_type: ffi::BSL_SecBlockType_e,
}

struct ParsedRule {
    rule_id: i64,
    description: Option<String>,
    role: api::BSL_SecRole_e,
    src: String,
    secsrc: String,
    dst: String,
    target_block_type: u64,
    location: api::BSL_PolicyLocation_e,
    failure_action: api::BSL_PolicyAction_e,
    correlation: Option<u64>,
    sec_block_type: api::BSL_SecBlockType_e,
    context_id: i64,
    security_context: SecurityContext,
    sc_parms: Value,
}

impl ParsedRule {
    fn from_json(value: &Value) -> BslResult<Self> {
        let item_object = value_object(value)?;
        let policy_rule_value = member(item_object, "policyrule")?;
        let policy_rule_object = value_object(policy_rule_value)?;
        let item: RuleSetItemJson =
            serde_json::from_value(value.clone()).map_err(|_| ffi::BSL_ERR_POLICY_CONFIG as c_int)?;

        let policy_rule = item.policyrule;
        let filter = policy_rule.filter;
        let spec = policy_rule.spec;

        let context_id = parse_i64_value(&spec.sc_id)?;
        let security_context = SecurityContext::from_context_id(context_id)?;
        let correlation = parse_correlation(policy_rule_object.get("correlation"))?;

        Ok(Self {
            rule_id: parse_i64_value(&filter.rule_id)?,
            description: policy_rule_object
                .get("desc")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            role: role_from_text(&filter.role)?,
            src: filter.src,
            secsrc: filter.secsrc,
            dst: filter.dst,
            target_block_type: parse_u64_value(&filter.tgt)?,
            location: location_from_text(&filter.loc)?,
            failure_action: parse_failure_action(policy_rule_object.get("policy_action_on_fail"))?,
            correlation,
            sec_block_type: service_from_text(&spec.svc)?,
            context_id,
            security_context,
            sc_parms: spec.sc_parms,
        })
    }

    fn record_correlation(&self, correlations: &mut HashMap<u64, CorrelationSpec>) -> BslResult {
        let Some(correlation) = self.correlation else {
            return Ok(());
        };

        let spec = CorrelationSpec {
            context_id: self.context_id,
            sec_block_type: self.sec_block_type,
        };

        if let Some(prev) = correlations.get(&correlation) {
            if *prev != spec {
                return Err(ffi::BSL_ERR_CORRELATION_MISMATCH as c_int);
            }
        } else {
            correlations.insert(correlation, spec);
        }

        Ok(())
    }
}

fn parse_failure_action(value: Option<&Value>) -> BslResult<api::BSL_PolicyAction_e> {
    match value {
        Some(value) => failure_action_from_text(value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?),
        None => Ok(ffi::BSL_POLICYACTION_NOTHING),
    }
}

fn parse_correlation(value: Option<&Value>) -> BslResult<Option<u64>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let correlation = parse_u64_value(value)?;
    if correlation == 0 {
        policy_config_err()
    } else {
        Ok(Some(correlation))
    }
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

unsafe fn option_add_or_erase<'a>(
    options: &'a mut PolicyOptions,
    opt_id: i64,
    value: &Value,
) -> BslResult<Option<&'a mut OwnedVariant>> {
    if value.is_null() {
        options.remove(&opt_id);
        Ok(None)
    } else {
        Ok(Some(add_policy_option(options, opt_id)))
    }
}

unsafe fn option_text(options: &mut PolicyOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    let text = value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    option.set_text(text)
}

unsafe fn option_int(options: &mut PolicyOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    option.set_int(parse_i64_value(value)?)
}

unsafe fn option_bool(options: &mut PolicyOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    option.set_int(if parse_boolish(value)? { 1 } else { 0 })
}

unsafe fn option_hex_bytes(options: &mut PolicyOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    let text = value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    let bytes = decode_hex(text)?;
    option.set_bytes(&bytes)
}

unsafe fn option_text_as_bytes(options: &mut PolicyOptions, opt_id: i64, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, opt_id, value)? else {
        return Ok(());
    };
    let text = value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    option.set_bytes(text.as_bytes())
}

unsafe fn option_cose_aad_scope(options: &mut PolicyOptions, value: &Value) -> BslResult {
    let Some(option) = option_add_or_erase(options, ffi::BSLX_COSESC_OPTION_AAD_SCOPE as i64, value)? else {
        return Ok(());
    };

    let object = value_object(value)?;
    let mut items = Vec::<ffi::BSLX_CoseSc_AadScope_Item_t>::with_capacity(object.len());
    for (key, flags_value) in object {
        items.push(ffi::BSLX_CoseSc_AadScope_Item_t {
            key: parse_i64_text(key)?,
            flags: parse_i64_value(flags_value)?,
        });
    }

    let ptr = if items.is_empty() { ptr::null() } else { items.as_ptr() };
    check_success(ffi::BSLX_CoseSc_SetAadScope(option.as_mut_ptr(), ptr, items.len()))
}

unsafe fn parse_bib_option(options: &mut PolicyOptions, key: &str, value: &Value) -> BslResult {
    match key {
        "key_name" => option_text(options, ffi::BSLX_BIB_OPT_KEY_ID as i64, value),
        "sha_variant" => option_int(options, ffi::BSLX_BIB_OPT_SHA_VARIANT as i64, value),
        "scope_flags" => option_int(options, ffi::BSLX_BIB_OPT_SCOPE as i64, value),
        "key_wrap" => option_bool(options, ffi::BSLX_BIB_OPT_USE_KEY_WRAP as i64, value),
        _ => policy_config_err(),
    }
}

unsafe fn parse_bcb_option(options: &mut PolicyOptions, key: &str, value: &Value) -> BslResult {
    match key {
        "key_name" => option_text(options, ffi::BSLX_BCB_OPT_KEY_ID as i64, value),
        "aes_variant" => option_int(options, ffi::BSLX_BCB_OPT_AES_VARIANT as i64, value),
        "aad_scope" => option_int(options, ffi::BSLX_BCB_OPT_SCOPE as i64, value),
        "key_wrap" => option_bool(options, ffi::BSLX_BCB_OPT_USE_KEY_WRAP as i64, value),
        _ => policy_config_err(),
    }
}

unsafe fn parse_cose_option(options: &mut PolicyOptions, key: &str, value: &Value) -> BslResult {
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

unsafe fn parse_cose_object(options: &mut PolicyOptions, object: &Map<String, Value>) -> BslResult {
    /*
     * COSE accepts both the legacy text key_name and the explicit key_id
     * alias for the same BSLX_COSESC_OPTION_KEY_ID option. serde_json's
     * default object map is key-sorted, so a policy object containing
     * {"key_name": null, "key_id": "..."} would otherwise add key_id
     * first and then erase it when key_name is visited. Process key_name
     * first and let the explicit key_id field win when both are present.
     */
    if let Some(key_name) = object.get("key_name") {
        parse_cose_option(options, "key_name", key_name)?;
    }

    for (key, entry_value) in object {
        if key == "key_name" {
            continue;
        }
        parse_cose_option(options, key, entry_value)?;
    }

    Ok(())
}

unsafe fn parse_sc_parms(context: SecurityContext, value: &Value) -> BslResult<PolicyOptions> {
    let mut options = PolicyOptions::new();

    if let Some(object) = value.as_object() {
        context.parse_object(&mut options, object)?;
    } else if let Some(array) = value.as_array() {
        for entry in array {
            let entry_object = value_object(entry)?;
            let key = member_str(entry_object, "id")?;
            let entry_value = member(entry_object, "value")?;
            context.parse_option(&mut options, key, entry_value)?;
        }
    } else {
        return policy_config_err();
    }

    Ok(options)
}

unsafe fn parse_one_rule(
    rule_set_item: &Value,
    policy: *mut api::BSLP_PolicyProvider_t,
    correlations: &mut HashMap<u64, CorrelationSpec>,
) -> BslResult {
    let parsed = ParsedRule::from_json(rule_set_item)?;
    parsed.record_correlation(correlations)?;

    let options = parse_sc_parms(parsed.security_context, &parsed.sc_parms)?;
    let mut predicate = StagedPredicate::new(parsed.location, &parsed.src, &parsed.secsrc, &parsed.dst)?;
    let mut rule = StagedRule::new(
        parsed.rule_id,
        parsed.description.as_deref(),
        parsed.context_id,
        parsed.role,
        parsed.sec_block_type,
        parsed.target_block_type,
        parsed.failure_action,
    )?;

    if let Some(correlation) = parsed.correlation {
        check_success(provider::BSLP_PolicyRule_SetCorrelation(rule.as_mut_ptr(), correlation))?;
    }

    move_options_into_rule(rule.as_mut_ptr(), options)?;
    check_success(provider::BSLP_PolicyProvider_AddRule(
        policy,
        rule.as_mut_ptr(),
        predicate.as_mut_ptr(),
    ))?;

    rule.disarm();
    predicate.disarm();
    Ok(())
}

unsafe fn parse_no_rule_actions(no_rules: Option<&Value>, policy: *mut api::BSLP_PolicyProvider_t) -> BslResult {
    let Some(no_rules) = no_rules else {
        return Ok(());
    };

    let object = value_object(no_rules)?;
    for (key, value) in object {
        let location = location_from_text(key)?;
        let action = failure_action_from_text(value.as_str().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?)?;
        if action == ffi::BSL_POLICYACTION_DROP_BLOCK {
            return policy_config_err();
        }
        provider::BSLP_PolicyProvider_SetNoRuleAction(policy, location, action);
    }
    Ok(())
}

fn validate_event_set(event_set: Option<&Value>) -> BslResult {
    let Some(event_set) = event_set else {
        return Ok(());
    };

    let Some(event_object) = event_set.as_object() else {
        return Ok(());
    };

    for events in event_object.values() {
        let Some(array) = events.as_array() else {
            continue;
        };
        for event in array {
            let event = value_object(event)?;
            member_str(event, "event_id")?;
            if let Some(actions) = event.get("actions") {
                let actions = actions.as_array().ok_or(ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
                for action in actions {
                    if action.as_str().is_none() {
                        return policy_config_err();
                    }
                }
            }
        }
    }
    Ok(())
}

unsafe fn parse_root_text(text: &str, policy: *mut api::BSLP_PolicyProvider_t) -> BslResult {
    if policy.is_null() {
        return arg_null_err();
    }

    let root: Value = serde_json::from_str(text).map_err(|_| ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    let root_object = value_object(&root)?;
    let document: PolicyDocument =
        serde_json::from_value(root.clone()).map_err(|_| ffi::BSL_ERR_POLICY_CONFIG as c_int)?;

    validate_event_set(root_object.get("event_set"))?;
    parse_no_rule_actions(root_object.get("policy_action_no_rules"), policy)?;

    let mut correlations = HashMap::<u64, CorrelationSpec>::new();
    let failures = document
        .policyrule_set
        .iter()
        .filter(|rule| parse_one_rule(rule, policy, &mut correlations).is_err())
        .count();

    if failures == 0 {
        Ok(())
    } else {
        policy_config_err()
    }
}

unsafe fn load_file(file_path: *const libc::c_char, policy: *mut api::BSLP_PolicyProvider_t) -> BslResult {
    if file_path.is_null() || policy.is_null() {
        return arg_null_err();
    }

    let path = Path::new(std::ffi::OsStr::from_bytes(CStr::from_ptr(file_path).to_bytes()));
    let mut file = File::open(path).map_err(|_| ffi::BSL_ERR_FAILURE as c_int)?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|_| ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    parse_root_text(&text, policy)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyParser_LoadFile(
    file_path: *const libc::c_char,
    policy: *mut api::BSLP_PolicyProvider_t,
) -> c_int {
    result_to_c_int(load_file(file_path, policy))
}

unsafe fn load_fd(infd: c_int, policy: *mut api::BSLP_PolicyProvider_t) -> BslResult {
    if policy.is_null() {
        return arg_null_err();
    }

    let dup_fd = libc::dup(infd);
    if dup_fd < 0 {
        return Err(ffi::BSL_ERR_FAILURE as c_int);
    }

    let mut file = File::from_raw_fd(dup_fd);
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|_| ffi::BSL_ERR_POLICY_CONFIG as c_int)?;
    parse_root_text(&text, policy)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyParser_LoadFd(
    infd: c_int,
    policy: *mut api::BSLP_PolicyProvider_t,
) -> c_int {
    result_to_c_int(load_fd(infd, policy))
}

unsafe fn add_bitstring_option_text(options: &mut PolicyOptions, opt_id: i64, text: &str) -> BslResult {
    add_policy_option(options, opt_id).set_text(text)
}

unsafe fn add_bitstring_option_int(options: &mut PolicyOptions, opt_id: i64, value: i64) -> BslResult {
    add_policy_option(options, opt_id).set_int(value)
}

#[derive(Clone, Copy, Debug)]
struct BitstringPolicy {
    sec_block_type: u64,
    policy_loc: u64,
    bundle_block_type: u64,
    policy_action_type: u64,
    sec_role: u64,
    use_wrapped_key: bool,
    policy_ignore: bool,
}

impl BitstringPolicy {
    const BUNDLE_BLOCK_TYPE_PRIMARY: u64 = 0;
    const BUNDLE_BLOCK_TYPE_PAYLOAD: u64 = 1;
    const BUNDLE_BLOCK_TYPE_BLOCK_192: u64 = 2;
    const BUNDLE_BLOCK_TYPE_BUNDLE_AGE: u64 = 3;

    fn decode(policy_bits: u64) -> Self {
        Self {
            sec_block_type: policy_bits & 0x01,
            policy_loc: (policy_bits >> 1) & 0x01,
            bundle_block_type: (policy_bits >> 2) & 0x03,
            policy_action_type: (policy_bits >> 4) & 0x03,
            sec_role: (policy_bits >> 6) & 0x03,
            use_wrapped_key: ((policy_bits >> 8) & 0x01) == 1,
            policy_ignore: ((policy_bits >> 9) & 0x01) == 1,
        }
    }

    unsafe fn sec_block_and_context(self, options: &mut PolicyOptions) -> BslResult<(ffi::BSL_SecBlockType_e, i64)> {
        if self.sec_block_type == 1 {
            add_bitstring_option_int(
                options,
                ffi::BSLX_BCB_OPT_SCOPE as i64,
                ffi::RFC9173_BCB_AADSCOPEFLAGID_INC_NONE as i64,
            )?;
            add_bitstring_option_int(
                options,
                ffi::BSLX_BCB_OPT_AES_VARIANT as i64,
                ffi::RFC9173_BCB_AES_VARIANT_A128GCM as i64,
            )?;
            if self.use_wrapped_key {
                add_bitstring_option_text(options, ffi::BSLX_BCB_OPT_KEY_ID as i64, "9103")?;
                add_bitstring_option_int(options, ffi::BSLX_BCB_OPT_USE_KEY_WRAP as i64, 1)?;
            } else {
                add_bitstring_option_text(options, ffi::BSLX_BCB_OPT_KEY_ID as i64, "9102")?;
                add_bitstring_option_int(options, ffi::BSLX_BCB_OPT_USE_KEY_WRAP as i64, 0)?;
            }
            Ok((ffi::BSL_SECBLOCKTYPE_BCB, ffi::RFC9173_CONTEXTID_BCB_AES_GCM as i64))
        } else {
            add_bitstring_option_int(options, ffi::BSLX_BIB_OPT_SCOPE as i64, 0)?;
            add_bitstring_option_int(
                options,
                ffi::BSLX_BIB_OPT_SHA_VARIANT as i64,
                ffi::RFC9173_BIB_SHA_HMAC512 as i64,
            )?;
            add_bitstring_option_text(options, ffi::BSLX_BIB_OPT_KEY_ID as i64, "9100")?;
            add_bitstring_option_int(options, ffi::BSLX_BIB_OPT_USE_KEY_WRAP as i64, 0)?;
            Ok((ffi::BSL_SECBLOCKTYPE_BIB, ffi::RFC9173_CONTEXTID_BIB_HMAC_SHA2 as i64))
        }
    }

    fn location(self) -> ffi::BSL_PolicyLocation_e {
        if self.policy_loc == 1 {
            ffi::BSL_POLICYLOCATION_CLIN
        } else {
            ffi::BSL_POLICYLOCATION_CLOUT
        }
    }

    fn target_block_type(self) -> u64 {
        match self.bundle_block_type {
            Self::BUNDLE_BLOCK_TYPE_PRIMARY => ffi::BSL_BLOCK_TYPE_PRIMARY as u64,
            Self::BUNDLE_BLOCK_TYPE_PAYLOAD => ffi::BSL_BLOCK_TYPE_PAYLOAD as u64,
            Self::BUNDLE_BLOCK_TYPE_BLOCK_192 => 192,
            Self::BUNDLE_BLOCK_TYPE_BUNDLE_AGE => ffi::BSL_BLOCK_TYPE_BUNDLE_AGE as u64,
            _ => ffi::BSL_BLOCK_TYPE_PRIMARY as u64,
        }
    }

    fn failure_action(self) -> ffi::BSL_PolicyAction_e {
        match self.policy_action_type {
            0 => ffi::BSL_POLICYACTION_NOTHING,
            1 => ffi::BSL_POLICYACTION_DROP_BLOCK,
            2 => ffi::BSL_POLICYACTION_DROP_BUNDLE,
            _ => ffi::BSL_POLICYACTION_NOTHING,
        }
    }

    fn role(self) -> ffi::BSL_SecRole_e {
        match self.sec_role {
            0 => ffi::BSL_SECROLE_SOURCE,
            1 => ffi::BSL_SECROLE_VERIFIER,
            2 => ffi::BSL_SECROLE_ACCEPTOR,
            _ => ffi::BSL_SECROLE_VERIFIER,
        }
    }

    fn source_pattern(self) -> &'static str {
        if self.policy_ignore {
            ""
        } else {
            "*:**"
        }
    }
}

unsafe fn register_policy_from_bitstring(policy_bits: u64, policy: *mut api::BSLP_PolicyProvider_t) -> BslResult {
    let policy_config = BitstringPolicy::decode(policy_bits);
    let mut options = PolicyOptions::new();
    let (sec_block_type, context_id) = policy_config.sec_block_and_context(&mut options)?;
    let description = format!("Policy: {:x}", policy_bits);

    let mut predicate = StagedPredicate::new(
        policy_config.location(),
        policy_config.source_pattern(),
        "*:**",
        "*:**",
    )?;
    let mut rule = StagedRule::new(
        0,
        Some(&description),
        context_id,
        policy_config.role(),
        sec_block_type,
        policy_config.target_block_type(),
        policy_config.failure_action(),
    )?;

    move_options_into_rule(rule.as_mut_ptr(), options)?;
    check_success(provider::BSLP_PolicyProvider_AddRule(
        policy,
        rule.as_mut_ptr(),
        predicate.as_mut_ptr(),
    ))?;

    rule.disarm();
    predicate.disarm();
    Ok(())
}

unsafe fn parse_bitstring_list(policies: *const libc::c_char, policy: *mut api::BSLP_PolicyProvider_t) -> BslResult {
    if policies.is_null() || policy.is_null() {
        return arg_null_err();
    }

    let Some(policy_text) = cstr_to_string(policies) else {
        return arg_null_err();
    };

    for token in policy_text.split(',').map(str::trim).filter(|token| !token.is_empty()) {
        let Ok(bits) = parse_i64_text(token) else {
            continue;
        };
        if bits < 0 || bits > i32::MAX as i64 {
            continue;
        }
        let _ = register_policy_from_bitstring(bits as u64, policy);
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyParser_FromBitstringList(
    policies: *const libc::c_char,
    policy: *mut api::BSLP_PolicyProvider_t,
) -> c_int {
    result_to_c_int(parse_bitstring_list(policies, policy))
}
