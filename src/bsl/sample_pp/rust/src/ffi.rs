#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[repr(C)]
pub(crate) struct BSLP_RustVariantMap_t {
    _private: [u8; 0],
}

unsafe extern "C" {
    pub(crate) fn BSLP_Rust_calloc(nmemb: usize, size: usize) -> *mut libc::c_void;
    pub(crate) fn BSLP_Rust_free(ptr: *mut libc::c_void);

    pub(crate) fn BSLP_Rust_VariantMap_New() -> *mut BSLP_RustVariantMap_t;
    pub(crate) fn BSLP_Rust_VariantMap_Destroy(self_: *mut BSLP_RustVariantMap_t);
    pub(crate) fn BSLP_Rust_VariantMap_Add(self_: *mut BSLP_RustVariantMap_t, key: i64) -> *mut BSL_Variant_t;
    pub(crate) fn BSLP_Rust_VariantMap_Erase(self_: *mut BSLP_RustVariantMap_t, key: i64);

    pub(crate) fn BSLP_Rust_PolicyRule_DescriptionInit(self_: *mut crate::api::BSLP_PolicyRule_t);
    pub(crate) fn BSLP_Rust_PolicyRule_DescriptionClear(self_: *mut crate::api::BSLP_PolicyRule_t);
    pub(crate) fn BSLP_Rust_PolicyRule_DescriptionSetCstr(
        self_: *mut crate::api::BSLP_PolicyRule_t,
        description: *const libc::c_char,
    );
    pub(crate) fn BSLP_Rust_PolicyRule_DescriptionGetCstr(
        self_: *const crate::api::BSLP_PolicyRule_t,
    ) -> *const libc::c_char;
    pub(crate) fn BSLP_Rust_PolicyRule_OptionsInit(self_: *mut crate::api::BSLP_PolicyRule_t);
    pub(crate) fn BSLP_Rust_PolicyRule_OptionsClear(self_: *mut crate::api::BSLP_PolicyRule_t);
    pub(crate) fn BSLP_Rust_PolicyRule_MoveOptionsFromRustMap(
        self_: *mut crate::api::BSLP_PolicyRule_t,
        options: *mut BSLP_RustVariantMap_t,
    ) -> libc::c_int;
    pub(crate) fn BSLP_Rust_PolicyRule_AddOption(
        self_: *mut crate::api::BSLP_PolicyRule_t,
        key: i64,
    ) -> *mut BSL_Variant_t;
    pub(crate) fn BSLP_Rust_PolicyRule_IsConsistent(self_: *const crate::api::BSLP_PolicyRule_t) -> bool;
    pub(crate) fn BSLP_Rust_PolicyRule_CopyOptionsToSecOper(
        self_: *const crate::api::BSLP_PolicyRule_t,
        sec_oper: *mut BSL_SecOper_t,
    );

    pub(crate) fn BSLP_Rust_PolicyPredicate_IsConsistent(
        self_: *const crate::api::BSLP_PolicyPredicate_t,
    ) -> bool;

    pub(crate) fn BSLP_Rust_Data_InitViewConst(data: *mut BSL_Data_t, ptr: *const u8, len: usize);
}
