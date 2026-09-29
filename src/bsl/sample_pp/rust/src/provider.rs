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
use crate::util::{
    add_policy_option, arg_null_err, check_success, check_success_as, failure_err, make_cstring,
    ok, policy_failed_err, policy_query_err, property_check_err, result_to_c_int, security_context_err, BslResult,
    PolicyOptions,
};
use libc::c_int;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::RwLock;

struct RuleEntry {
    rule: Box<PolicyRule>,
    predicate: Box<PolicyPredicate>,
}

struct PolicyProvider {
    pp_id: u64,
    rules: RwLock<Vec<RuleEntry>>,
    no_rule_actions: RwLock<HashMap<ffi::BSL_PolicyLocation_e, ffi::BSL_PolicyAction_e>>,
}

struct PolicyPredicate {
    location: ffi::BSL_PolicyLocation_e,
    src_eid_pattern: ffi::BSL_HostEIDPattern_t,
    secsrc_eid_pattern: ffi::BSL_HostEIDPattern_t,
    dst_eid_pattern: ffi::BSL_HostEIDPattern_t,
}

impl PolicyPredicate {
    unsafe fn blank() -> Self {
        let mut predicate = Self {
            location: 0,
            src_eid_pattern: MaybeUninit::<ffi::BSL_HostEIDPattern_t>::zeroed().assume_init(),
            secsrc_eid_pattern: MaybeUninit::<ffi::BSL_HostEIDPattern_t>::zeroed().assume_init(),
            dst_eid_pattern: MaybeUninit::<ffi::BSL_HostEIDPattern_t>::zeroed().assume_init(),
        };
        ffi::BSL_HostEIDPattern_Init(&mut predicate.src_eid_pattern);
        ffi::BSL_HostEIDPattern_Init(&mut predicate.secsrc_eid_pattern);
        ffi::BSL_HostEIDPattern_Init(&mut predicate.dst_eid_pattern);
        predicate
    }

    unsafe fn from_cstr(
        location: ffi::BSL_PolicyLocation_e,
        src_eid_pattern: *const libc::c_char,
        secsrc_eid_pattern: *const libc::c_char,
        dst_eid_pattern: *const libc::c_char,
    ) -> BslResult<Self> {
        if src_eid_pattern.is_null() || secsrc_eid_pattern.is_null() || dst_eid_pattern.is_null() {
            return arg_null_err();
        }

        let mut predicate = Self::blank();
        predicate.location = location;
        check_success_as(
            ffi::BSL_HostEIDPattern_DecodeFromText(&mut predicate.src_eid_pattern, src_eid_pattern)
                | ffi::BSL_HostEIDPattern_DecodeFromText(&mut predicate.secsrc_eid_pattern, secsrc_eid_pattern)
                | ffi::BSL_HostEIDPattern_DecodeFromText(&mut predicate.dst_eid_pattern, dst_eid_pattern),
            ffi::BSL_ERR_HOST_CALLBACK_FAILED as c_int,
        )?;

        if predicate.is_consistent() {
            Ok(predicate)
        } else {
            property_check_err()
        }
    }

    fn is_consistent(&self) -> bool {
        (self.location >= ffi::BSL_POLICYLOCATION_APPIN)
            && (self.location <= ffi::BSL_POLICYLOCATION_CLOUT)
            && !self.src_eid_pattern.handle.is_null()
            && !self.secsrc_eid_pattern.handle.is_null()
            && !self.dst_eid_pattern.handle.is_null()
    }

    unsafe fn matches(
        &self,
        location: ffi::BSL_PolicyLocation_e,
        src_eid: *const ffi::BSL_HostEID_t,
        dst_eid: *const ffi::BSL_HostEID_t,
    ) -> bool {
        (self.location == location)
            && ffi::BSL_HostEIDPattern_IsMatch(&self.src_eid_pattern, src_eid)
            && ffi::BSL_HostEIDPattern_IsMatch(&self.dst_eid_pattern, dst_eid)
    }
}

impl Drop for PolicyPredicate {
    fn drop(&mut self) {
        unsafe {
            ffi::BSL_HostEIDPattern_Deinit(&mut self.dst_eid_pattern);
            ffi::BSL_HostEIDPattern_Deinit(&mut self.secsrc_eid_pattern);
            ffi::BSL_HostEIDPattern_Deinit(&mut self.src_eid_pattern);
        }
    }
}

#[allow(dead_code)]
struct PolicyRule {
    rule_id: i64,
    description: String,
    role: ffi::BSL_SecRole_e,
    target_block_type: u64,
    sec_block_type: ffi::BSL_SecBlockType_e,
    context_id: i64,
    options: PolicyOptions,
    failure_action_code: ffi::BSL_PolicyAction_e,
    correlation_id: u64,
}

impl PolicyRule {
    fn blank() -> Self {
        Self {
            rule_id: 0,
            description: String::new(),
            role: 0,
            target_block_type: 0,
            sec_block_type: 0,
            context_id: 0,
            options: PolicyOptions::new(),
            failure_action_code: ffi::BSL_POLICYACTION_UNDEFINED,
            correlation_id: 0,
        }
    }

    unsafe fn from_cstr(
        rule_id: i64,
        description: *const libc::c_char,
        context_id: i64,
        role: ffi::BSL_SecRole_e,
        sec_block_type: ffi::BSL_SecBlockType_e,
        target_block_type: u64,
        failure_action_code: ffi::BSL_PolicyAction_e,
    ) -> BslResult<Self> {
        let mut rule = Self::blank();
        rule.rule_id = rule_id;
        rule.description = if description.is_null() {
            String::new()
        } else {
            CStr::from_ptr(description).to_string_lossy().into_owned()
        };
        rule.context_id = context_id;
        rule.role = role;
        rule.sec_block_type = sec_block_type;
        rule.target_block_type = target_block_type;
        rule.failure_action_code = failure_action_code;

        if rule.is_consistent() {
            Ok(rule)
        } else {
            property_check_err()
        }
    }

    fn is_consistent(&self) -> bool {
        (self.role >= ffi::BSL_SECROLE_SOURCE)
            && (self.role <= ffi::BSL_SECROLE_ACCEPTOR)
            && (self.sec_block_type >= ffi::BSL_SECBLOCKTYPE_BIB)
            && (self.sec_block_type <= ffi::BSL_SECBLOCKTYPE_BCB)
            && (self.context_id > 0)
            && (self.failure_action_code != ffi::BSL_POLICYACTION_UNDEFINED)
    }

    unsafe fn add_option(&mut self, opt_id: i64) -> *mut ffi::BSL_Variant_t {
        add_policy_option(&mut self.options, opt_id).as_mut_ptr()
    }

    unsafe fn copy_options_to_sec_oper(&self, sec_oper: *mut ffi::BSL_SecOper_t) -> BslResult {
        if sec_oper.is_null() {
            return arg_null_err();
        }

        for (opt_id, option) in &self.options {
            let dest = ffi::BSL_SecOper_AddOption(sec_oper, *opt_id);
            option.copy_to(dest)?;
        }
        Ok(())
    }

    unsafe fn evaluate_as_sec_oper(
        &self,
        predicate: &PolicyPredicate,
        sec_oper: *mut ffi::BSL_SecOper_t,
        bundle: *const ffi::BSL_BundleRef_t,
        location: ffi::BSL_PolicyLocation_e,
    ) -> BslResult {
        if sec_oper.is_null() || bundle.is_null() {
            return arg_null_err();
        }

        let primary = PrimaryBlock::from_bundle(bundle)?;
        if !predicate.matches(
            location,
            primary.inner.field_src_node_id,
            primary.inner.field_dest_eid,
        ) {
            return property_check_err();
        }

        let target_block_num = get_target_block_id(bundle, self.target_block_type)?;
        ffi::BSL_SecOper_Populate(
            sec_oper,
            self.context_id,
            target_block_num,
            0,
            self.sec_block_type,
            self.role,
            self.failure_action_code,
            self.correlation_id,
        );
        self.copy_options_to_sec_oper(sec_oper)
    }
}

unsafe fn provider_ref<'a>(ptr: *const api::BSLP_PolicyProvider_t) -> Option<&'a PolicyProvider> {
    (ptr as *const PolicyProvider).as_ref()
}

unsafe fn provider_mut<'a>(ptr: *mut api::BSLP_PolicyProvider_t) -> Option<&'a mut PolicyProvider> {
    (ptr as *mut PolicyProvider).as_mut()
}

unsafe fn predicate_ref<'a>(ptr: *const api::BSLP_PolicyPredicate_t) -> Option<&'a PolicyPredicate> {
    if ptr.is_null() || (*ptr)._private.is_null() {
        None
    } else {
        ((*ptr)._private as *const PolicyPredicate).as_ref()
    }
}

unsafe fn rule_ref<'a>(ptr: *const api::BSLP_PolicyRule_t) -> Option<&'a PolicyRule> {
    if ptr.is_null() || (*ptr)._private.is_null() {
        None
    } else {
        ((*ptr)._private as *const PolicyRule).as_ref()
    }
}

unsafe fn rule_mut<'a>(ptr: *mut api::BSLP_PolicyRule_t) -> Option<&'a mut PolicyRule> {
    if ptr.is_null() || (*ptr)._private.is_null() {
        None
    } else {
        ((*ptr)._private as *mut PolicyRule).as_mut()
    }
}

unsafe fn take_predicate(ptr: *mut api::BSLP_PolicyPredicate_t) -> BslResult<Box<PolicyPredicate>> {
    if ptr.is_null() || (*ptr)._private.is_null() {
        return arg_null_err();
    }
    let handle = (*ptr)._private as *mut PolicyPredicate;
    (*ptr)._private = ptr::null_mut();
    Ok(Box::from_raw(handle))
}

unsafe fn take_rule(ptr: *mut api::BSLP_PolicyRule_t) -> BslResult<Box<PolicyRule>> {
    if ptr.is_null() || (*ptr)._private.is_null() {
        return arg_null_err();
    }
    let handle = (*ptr)._private as *mut PolicyRule;
    (*ptr)._private = ptr::null_mut();
    Ok(Box::from_raw(handle))
}

struct PrimaryBlock {
    inner: ffi::BSL_PrimaryBlock_t,
}

impl PrimaryBlock {
    unsafe fn from_bundle(bundle: *const api::BSL_BundleRef_t) -> BslResult<Self> {
        if bundle.is_null() {
            return arg_null_err();
        }

        let mut primary = Self {
            inner: MaybeUninit::<ffi::BSL_PrimaryBlock_t>::zeroed().assume_init(),
        };
        ffi::BSL_PrimaryBlock_Init(&mut primary.inner);
        check_success_as(
            ffi::BSL_BundleCtx_GetBundleMetadata(bundle, &mut primary.inner),
            ffi::BSL_ERR_HOST_CALLBACK_FAILED as c_int,
        )?;
        Ok(primary)
    }

    fn block_numbers(&self) -> &[u64] {
        if self.inner.block_numbers.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.inner.block_numbers, self.inner.block_count) }
        }
    }
}

impl Drop for PrimaryBlock {
    fn drop(&mut self) {
        unsafe {
            ffi::BSL_PrimaryBlock_deinit(&mut self.inner);
        }
    }
}

struct OwnedSecOper {
    ptr: *mut ffi::BSL_SecOper_t,
}

impl OwnedSecOper {
    unsafe fn new() -> BslResult<Self> {
        let size = ffi::BSL_SecOper_Sizeof();
        let ptr = ffi::BSL_calloc(1, size) as *mut ffi::BSL_SecOper_t;
        if ptr.is_null() {
            return failure_err();
        }

        ffi::BSL_SecOper_Init(ptr);
        Ok(Self { ptr })
    }

    fn as_ptr(&self) -> *const ffi::BSL_SecOper_t {
        self.ptr
    }

    fn as_mut_ptr(&mut self) -> *mut ffi::BSL_SecOper_t {
        self.ptr
    }

    unsafe fn free_after_move(mut self) {
        let ptr = self.ptr;
        self.ptr = ptr::null_mut();
        ffi::BSL_free(ptr.cast());
    }
}

impl Drop for OwnedSecOper {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                ffi::BSL_SecOper_Deinit(self.ptr);
                ffi::BSL_free(self.ptr.cast());
            }
        }
    }
}

struct OwnedSecurityAction {
    ptr: *mut ffi::BSL_SecurityAction_t,
}

impl OwnedSecurityAction {
    unsafe fn new() -> BslResult<Self> {
        let size = ffi::BSL_SecurityAction_Sizeof();
        let ptr = ffi::BSL_calloc(1, size) as *mut ffi::BSL_SecurityAction_t;
        if ptr.is_null() {
            return failure_err();
        }

        ffi::BSL_SecurityAction_Init(ptr);
        Ok(Self { ptr })
    }

    fn as_mut_ptr(&self) -> *mut ffi::BSL_SecurityAction_t {
        self.ptr
    }
}

impl Drop for OwnedSecurityAction {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                ffi::BSL_SecurityAction_Deinit(self.ptr);
                ffi::BSL_free(self.ptr.cast());
            }
        }
    }
}

unsafe fn get_target_block_id(bundle: *const api::BSL_BundleRef_t, target_block_type: u64) -> BslResult<u64> {
    if target_block_type == ffi::BSL_BLOCK_TYPE_PRIMARY as u64 {
        return Ok(0);
    }

    let primary = PrimaryBlock::from_bundle(bundle)?;
    for block_num in primary.block_numbers() {
        let mut meta = MaybeUninit::<ffi::BSL_CanonicalBlock_t>::zeroed().assume_init();
        let err = ffi::BSL_BundleCtx_GetBlockMetadata(bundle, *block_num, &mut meta);
        if err == ok() && meta.type_code == target_block_type {
            return Ok(*block_num);
        }
    }

    security_context_err()
}

unsafe fn sec_oper_has_conflict(new_sec_oper: *const ffi::BSL_SecOper_t, secops: &[OwnedSecOper]) -> bool {
    if ffi::BSL_SecOper_IsBIB(new_sec_oper) && !ffi::BSL_SecOper_IsRoleSource(new_sec_oper) {
        let target = ffi::BSL_SecOper_GetTargetBlockNum(new_sec_oper);
        secops.iter().any(|candidate| {
            ffi::BSL_SecOper_IsBCB(candidate.as_ptr())
                && ffi::BSL_SecOper_IsRoleVerifier(candidate.as_ptr())
                && ffi::BSL_SecOper_GetTargetBlockNum(candidate.as_ptr()) == target
        })
    } else {
        false
    }
}

unsafe fn order_sec_oper(secops: &mut Vec<OwnedSecOper>, mut new_sec_oper: OwnedSecOper) {
    let mut insert_at = None;
    let new_ptr = new_sec_oper.as_mut_ptr();

    for (index, comp) in secops.iter().enumerate() {
        let comp_ptr = comp.as_ptr();
        let new_target = ffi::BSL_SecOper_GetTargetBlockNum(new_ptr);
        let comp_target = ffi::BSL_SecOper_GetTargetBlockNum(comp_ptr);
        let new_sec_block = ffi::BSL_SecOper_GetSecurityBlockNum(new_ptr);
        let comp_sec_block = ffi::BSL_SecOper_GetSecurityBlockNum(comp_ptr);

        if comp_target == new_target {
            let one_is_bib = ffi::BSL_SecOper_IsBIB(new_ptr) ^ ffi::BSL_SecOper_IsBIB(comp_ptr);
            if !one_is_bib {
                ffi::BSL_SecOper_SetConclusion(new_ptr, ffi::BSL_SECOP_CONCLUSION_INVALID);
            }

            let new_goes_after = ffi::BSL_SecOper_IsBIB(new_ptr) ^ ffi::BSL_SecOper_IsRoleSource(new_ptr);
            insert_at = Some(if new_goes_after { index + 1 } else { index });
            break;
        }

        if comp_target == new_sec_block {
            insert_at = Some(index);
            break;
        }

        if new_target == comp_sec_block {
            insert_at = Some(index + 1);
            break;
        }

        if comp_sec_block == new_sec_block {
            insert_at = Some(if comp_target != new_target { index } else { index + 1 });
            break;
        }
    }

    if let Some(index) = insert_at {
        secops.insert(index, new_sec_oper);
    } else {
        secops.push(new_sec_oper);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_Deinit(_user_data: *mut libc::c_void) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyProvider_New(pp_id: u64) -> *mut api::BSLP_PolicyProvider_t {
    if pp_id == 0 {
        return ptr::null_mut();
    }

    let provider = PolicyProvider {
        pp_id,
        rules: RwLock::new(Vec::new()),
        no_rule_actions: RwLock::new(HashMap::new()),
    };
    Box::into_raw(Box::new(provider)) as *mut api::BSLP_PolicyProvider_t
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyProvider_Destroy(self_: *mut api::BSLP_PolicyProvider_t) {
    if !self_.is_null() {
        drop(Box::from_raw(self_ as *mut PolicyProvider));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyProvider_RuleCount(self_: *mut api::BSLP_PolicyProvider_t) -> usize {
    let Some(provider) = provider_ref(self_) else {
        return 0;
    };
    match provider.rules.read() {
        Ok(rules) => rules.len(),
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyProvider_SetNoRuleAction(
    self_: *mut api::BSLP_PolicyProvider_t,
    location: api::BSL_PolicyLocation_e,
    action: api::BSL_PolicyAction_e,
) {
    let Some(provider) = provider_mut(self_) else {
        return;
    };

    if action == ffi::BSL_POLICYACTION_UNDEFINED || action == ffi::BSL_POLICYACTION_DROP_BLOCK {
        return;
    }

    let Ok(mut actions) = provider.no_rule_actions.write() else {
        return;
    };

    if action == ffi::BSL_POLICYACTION_NOTHING {
        actions.remove(&location);
    } else {
        actions.insert(location, action);
    }
}

unsafe fn policy_provider_add_rule(
    self_: *mut api::BSLP_PolicyProvider_t,
    rule: *mut api::BSLP_PolicyRule_t,
    predicate: *mut api::BSLP_PolicyPredicate_t,
) -> BslResult {
    let Some(provider) = provider_mut(self_) else {
        return arg_null_err();
    };
    let Some(rule_ref) = rule_ref(rule) else {
        return arg_null_err();
    };
    let Some(predicate_ref) = predicate_ref(predicate) else {
        return arg_null_err();
    };
    if !rule_ref.is_consistent() || !predicate_ref.is_consistent() {
        return property_check_err();
    }

    let mut rules = provider.rules.write().map_err(|_| ffi::BSL_ERR_FAILURE as c_int)?;
    let rule_box = take_rule(rule)?;
    let predicate_box = take_predicate(predicate)?;
    rules.push(RuleEntry {
        rule: rule_box,
        predicate: predicate_box,
    });
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyProvider_AddRule(
    self_: *mut api::BSLP_PolicyProvider_t,
    rule: *mut api::BSLP_PolicyRule_t,
    predicate: *mut api::BSLP_PolicyPredicate_t,
) -> c_int {
    result_to_c_int(policy_provider_add_rule(self_, rule, predicate))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyPredicate_Init(self_: *mut api::BSLP_PolicyPredicate_t) {
    if self_.is_null() {
        return;
    }

    let predicate = Box::new(PolicyPredicate::blank());
    (*self_)._private = Box::into_raw(predicate).cast();
}

unsafe fn policy_predicate_init_from(
    self_: *mut api::BSLP_PolicyPredicate_t,
    location: api::BSL_PolicyLocation_e,
    src_eid_pattern: *const libc::c_char,
    secsrc_eid_pattern: *const libc::c_char,
    dst_eid_pattern: *const libc::c_char,
) -> BslResult {
    if self_.is_null() {
        return arg_null_err();
    }
    (*self_)._private = ptr::null_mut();

    let predicate = PolicyPredicate::from_cstr(location, src_eid_pattern, secsrc_eid_pattern, dst_eid_pattern)?;
    (*self_)._private = Box::into_raw(Box::new(predicate)).cast();
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyPredicate_InitFrom(
    self_: *mut api::BSLP_PolicyPredicate_t,
    location: api::BSL_PolicyLocation_e,
    src_eid_pattern: *const libc::c_char,
    secsrc_eid_pattern: *const libc::c_char,
    dst_eid_pattern: *const libc::c_char,
) -> c_int {
    result_to_c_int(policy_predicate_init_from(
        self_,
        location,
        src_eid_pattern,
        secsrc_eid_pattern,
        dst_eid_pattern,
    ))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyPredicate_Deinit(self_: *mut api::BSLP_PolicyPredicate_t) {
    if self_.is_null() || (*self_)._private.is_null() {
        return;
    }
    drop(Box::from_raw((*self_)._private as *mut PolicyPredicate));
    (*self_)._private = ptr::null_mut();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyPredicate_Move(
    self_: *mut api::BSLP_PolicyPredicate_t,
    src: *mut api::BSLP_PolicyPredicate_t,
) {
    if self_.is_null() || src.is_null() || self_ == src {
        return;
    }
    BSLP_PolicyPredicate_Deinit(self_);
    (*self_)._private = (*src)._private;
    (*src)._private = ptr::null_mut();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyPredicate_IsMatch(
    self_: *const api::BSLP_PolicyPredicate_t,
    location: api::BSL_PolicyLocation_e,
    src_eid: *const api::BSL_HostEID_t,
    dst_eid: *const api::BSL_HostEID_t,
) -> bool {
    let Some(predicate) = predicate_ref(self_) else {
        return false;
    };
    predicate.matches(location, src_eid, dst_eid)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyRule_Init(self_: *mut api::BSLP_PolicyRule_t) {
    if self_.is_null() {
        return;
    }

    let rule = Box::new(PolicyRule::blank());
    (*self_)._private = Box::into_raw(rule).cast();
}

unsafe fn policy_rule_init_from(
    self_: *mut api::BSLP_PolicyRule_t,
    rule_id: i64,
    description: *const libc::c_char,
    context_id: i64,
    role: api::BSL_SecRole_e,
    sec_block_type: api::BSL_SecBlockType_e,
    target_block_type: u64,
    failure_action_code: api::BSL_PolicyAction_e,
) -> BslResult {
    if self_.is_null() {
        return arg_null_err();
    }
    (*self_)._private = ptr::null_mut();

    let rule = PolicyRule::from_cstr(
        rule_id,
        description,
        context_id,
        role,
        sec_block_type,
        target_block_type,
        failure_action_code,
    )?;
    (*self_)._private = Box::into_raw(Box::new(rule)).cast();
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyRule_InitFrom(
    self_: *mut api::BSLP_PolicyRule_t,
    rule_id: i64,
    description: *const libc::c_char,
    context_id: i64,
    role: api::BSL_SecRole_e,
    sec_block_type: api::BSL_SecBlockType_e,
    target_block_type: u64,
    failure_action_code: api::BSL_PolicyAction_e,
) -> c_int {
    result_to_c_int(policy_rule_init_from(
        self_,
        rule_id,
        description,
        context_id,
        role,
        sec_block_type,
        target_block_type,
        failure_action_code,
    ))
}

unsafe fn policy_rule_set_correlation(self_: *mut api::BSLP_PolicyRule_t, corr_id: u64) -> BslResult {
    let Some(rule) = rule_mut(self_) else {
        return arg_null_err();
    };
    if corr_id == 0 {
        return property_check_err();
    }
    rule.correlation_id = corr_id;
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyRule_SetCorrelation(
    self_: *mut api::BSLP_PolicyRule_t,
    corr_id: u64,
) -> c_int {
    result_to_c_int(policy_rule_set_correlation(self_, corr_id))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyRule_Deinit(self_: *mut api::BSLP_PolicyRule_t) {
    if self_.is_null() || (*self_)._private.is_null() {
        return;
    }
    drop(Box::from_raw((*self_)._private as *mut PolicyRule));
    (*self_)._private = ptr::null_mut();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyRule_Move(
    self_: *mut api::BSLP_PolicyRule_t,
    src: *mut api::BSLP_PolicyRule_t,
) {
    if self_.is_null() || src.is_null() || self_ == src {
        return;
    }
    BSLP_PolicyRule_Deinit(self_);
    (*self_)._private = (*src)._private;
    (*src)._private = ptr::null_mut();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyRule_AddOption(
    self_: *mut api::BSLP_PolicyRule_t,
    opt_id: i64,
) -> *mut api::BSL_Variant_t {
    let Some(rule) = rule_mut(self_) else {
        return ptr::null_mut();
    };
    rule.add_option(opt_id)
}

unsafe fn policy_rule_evaluate_as_sec_oper(
    self_: *const api::BSLP_PolicyRule_t,
    predicate: *const api::BSLP_PolicyPredicate_t,
    sec_oper: *mut api::BSL_SecOper_t,
    bundle: *const api::BSL_BundleRef_t,
    location: api::BSL_PolicyLocation_e,
) -> BslResult {
    let Some(rule) = rule_ref(self_) else {
        return arg_null_err();
    };
    let Some(predicate) = predicate_ref(predicate) else {
        return arg_null_err();
    };
    rule.evaluate_as_sec_oper(predicate, sec_oper, bundle, location)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_PolicyRule_EvaluateAsSecOper(
    self_: *const api::BSLP_PolicyRule_t,
    predicate: *const api::BSLP_PolicyPredicate_t,
    sec_oper: *mut api::BSL_SecOper_t,
    bundle: *const api::BSL_BundleRef_t,
    location: api::BSL_PolicyLocation_e,
) -> c_int {
    result_to_c_int(policy_rule_evaluate_as_sec_oper(
        self_, predicate, sec_oper, bundle, location,
    ))
}

unsafe fn query_policy(
    user_data: *mut libc::c_void,
    output_action_set: *mut api::BSL_SecurityActionSet_t,
    bundle: *const api::BSL_BundleRef_t,
    location: api::BSL_PolicyLocation_e,
) -> BslResult {
    let Some(provider) = provider_ref(user_data as *const api::BSLP_PolicyProvider_t) else {
        return arg_null_err();
    };
    if output_action_set.is_null() || bundle.is_null() {
        return arg_null_err();
    }

    let primary = PrimaryBlock::from_bundle(bundle)?;
    let action = OwnedSecurityAction::new()?;
    let mut matched = 0usize;
    let mut secops = Vec::<OwnedSecOper>::new();

    let rules_guard = provider.rules.read().map_err(|_| ffi::BSL_ERR_FAILURE as c_int)?;
    for entry in rules_guard.iter() {
        if !entry.rule.is_consistent()
            || !entry.predicate.matches(
                location,
                primary.inner.field_src_node_id,
                primary.inner.field_dest_eid,
            )
        {
            continue;
        }
        if get_target_block_id(bundle, entry.rule.target_block_type).is_err() {
            continue;
        }

        matched += 1;
        let mut sec_oper = match OwnedSecOper::new() {
            Ok(sec_oper) => sec_oper,
            Err(_) => {
                ffi::BSL_SecurityAction_IncrError(action.as_mut_ptr());
                continue;
            }
        };

        if entry
            .rule
            .evaluate_as_sec_oper(&entry.predicate, sec_oper.as_mut_ptr(), bundle, location)
            .is_err()
        {
            ffi::BSL_SecurityAction_IncrError(action.as_mut_ptr());
            continue;
        }
        order_sec_oper(&mut secops, sec_oper);
    }
    drop(rules_guard);

    if matched == 0 {
        let drop_bundle = provider
            .no_rule_actions
            .read()
            .ok()
            .and_then(|actions| actions.get(&location).copied())
            .filter(|action| *action == ffi::BSL_POLICYACTION_DROP_BUNDLE);
        if let Some(action_code) = drop_bundle {
            ffi::BSL_SecurityActionSet_SetImmediate(
                output_action_set,
                action_code,
                ffi::BSL_REASONCODE_MISSING_SECOP,
            );
        }
    }

    if secops.iter().any(|secop| sec_oper_has_conflict(secop.as_ptr(), &secops)) {
        return policy_query_err();
    }

    for secop in secops.drain(..) {
        ffi::BSL_SecurityAction_AppendSecOper(action.as_mut_ptr(), secop.as_ptr() as *mut ffi::BSL_SecOper_t);
        secop.free_after_move();
    }

    check_success(ffi::BSL_SecurityActionSet_AppendAction(
        output_action_set,
        action.as_mut_ptr(),
    ))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_QueryPolicy(
    user_data: *mut libc::c_void,
    output_action_set: *mut api::BSL_SecurityActionSet_t,
    bundle: *const api::BSL_BundleRef_t,
    location: api::BSL_PolicyLocation_e,
) -> c_int {
    result_to_c_int(query_policy(user_data, output_action_set, bundle, location))
}

unsafe fn log_policy_warning(line: u32, message: &'static [u8]) {
    ffi::BSL_LogEvent(
        libc::LOG_WARNING,
        b"sample_pp/rust/src/provider.rs\0".as_ptr().cast(),
        line as c_int,
        b"handle_failures\0".as_ptr().cast(),
        message.as_ptr().cast(),
    );
}

unsafe fn log_policy_warning_text(line: u32, message: String) {
    let Ok(message) = CString::new(message) else {
        return;
    };
    ffi::BSL_LogEvent(
        libc::LOG_WARNING,
        b"sample_pp/rust/src/provider.rs\0".as_ptr().cast(),
        line as c_int,
        b"handle_failures\0".as_ptr().cast(),
        message.as_ptr(),
    );
}

unsafe fn handle_failures(bundle: *mut api::BSL_BundleRef_t, sec_oper: *mut api::BSL_SecOper_t) -> BslResult {
    match ffi::BSL_SecOper_GetPolicyAction(sec_oper) {
        action if action == ffi::BSL_POLICYACTION_NOTHING => {
            log_policy_warning(
                line!(),
                b"Instructed to do nothing for failed security operation\0",
            );
            Ok(())
        }
        action if action == ffi::BSL_POLICYACTION_DROP_BLOCK => {
            log_policy_warning(
                line!(),
                b"***** Dropping block over which security operation failed *******\0",
            );
            check_success(ffi::BSL_BundleCtx_RemoveBlock(
                bundle,
                ffi::BSL_SecOper_GetTargetBlockNum(sec_oper),
            ))
        }
        action if action == ffi::BSL_POLICYACTION_DROP_BUNDLE => {
            let block_num = ffi::BSL_SecOper_GetTargetBlockNum(sec_oper);
            log_policy_warning_text(
                line!(),
                format!("Deleting bundle due to block target num {} security failure", block_num),
            );
            log_policy_warning(
                line!(),
                b"***** Delete bundle due to failed security operation *******\0",
            );
            check_success(ffi::BSL_BundleCtx_DeleteBundle(
                bundle,
                ffi::BSL_SecOper_GetReasonCode(sec_oper),
            ))
        }
        _ => policy_failed_err(),
    }
}

unsafe fn finalize_policy(
    user_data: *mut libc::c_void,
    action_set: *const api::BSL_SecurityActionSet_t,
    bundle: *mut api::BSL_BundleRef_t,
) -> BslResult {
    let Some(provider) = provider_ref(user_data as *const api::BSLP_PolicyProvider_t) else {
        return arg_null_err();
    };
    if action_set.is_null() || bundle.is_null() {
        return arg_null_err();
    }

    for act_idx in 0..ffi::BSL_SecurityActionSet_CountActions(action_set) {
        let action = ffi::BSL_SecurityActionSet_GetActionAtIndex(action_set, act_idx) as *mut ffi::BSL_SecurityAction_t;
        if action.is_null() || ffi::BSL_SecurityAction_GetPPID(action) != provider.pp_id {
            continue;
        }

        for sec_idx in 0..ffi::BSL_SecurityAction_CountSecOpers(action) {
            let sec_oper = ffi::BSL_SecurityAction_GetSecOperAtIndex(action, sec_idx);
            if sec_oper.is_null() {
                continue;
            }

            if ffi::BSL_SecOper_GetConclusion(sec_oper) != ffi::BSL_SECOP_CONCLUSION_SUCCESS {
                handle_failures(bundle, sec_oper)?;
            }
        }
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BSLP_FinalizePolicy(
    user_data: *mut libc::c_void,
    action_set: *const api::BSL_SecurityActionSet_t,
    bundle: *mut api::BSL_BundleRef_t,
) -> c_int {
    result_to_c_int(finalize_policy(user_data, action_set, bundle))
}

pub unsafe fn move_options_into_rule(rule: *mut api::BSLP_PolicyRule_t, options: PolicyOptions) -> BslResult {
    let Some(rule) = rule_mut(rule) else {
        return arg_null_err();
    };
    rule.options = options;
    Ok(())
}

pub unsafe fn init_rule_from_rust(
    rule: *mut api::BSLP_PolicyRule_t,
    rule_id: i64,
    description: Option<&str>,
    context_id: i64,
    role: api::BSL_SecRole_e,
    sec_block_type: api::BSL_SecBlockType_e,
    target_block_type: u64,
    failure_action_code: api::BSL_PolicyAction_e,
) -> BslResult {
    let description_c = match description {
        Some(value) => Some(make_cstring(value)?),
        None => None,
    };
    let description_ptr = description_c.as_ref().map_or(ptr::null(), |value| value.as_ptr());
    policy_rule_init_from(
        rule,
        rule_id,
        description_ptr,
        context_id,
        role,
        sec_block_type,
        target_block_type,
        failure_action_code,
    )
}

pub unsafe fn init_predicate_from_rust(
    predicate: *mut api::BSLP_PolicyPredicate_t,
    location: api::BSL_PolicyLocation_e,
    src: &str,
    secsrc: &str,
    dst: &str,
) -> BslResult {
    let src_c = make_cstring(src)?;
    let secsrc_c = make_cstring(secsrc)?;
    let dst_c = make_cstring(dst)?;
    policy_predicate_init_from(predicate, location, src_c.as_ptr(), secsrc_c.as_ptr(), dst_c.as_ptr())
}
