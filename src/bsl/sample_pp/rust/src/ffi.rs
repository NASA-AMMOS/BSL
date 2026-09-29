#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

unsafe extern "C" {
    pub(crate) fn BSLP_Rust_calloc(nmemb: usize, size: usize) -> *mut libc::c_void;
    pub(crate) fn BSLP_Rust_free(ptr: *mut libc::c_void);
    pub(crate) fn BSLP_Rust_Data_InitViewConst(data: *mut BSL_Data_t, ptr: *const u8, len: usize);
}
