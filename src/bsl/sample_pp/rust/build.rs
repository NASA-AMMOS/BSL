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

use std::env;
use std::path::PathBuf;

const BINDGEN_WRAPPER: &str = r#"
#include "bsl/BSLConfig.h"
#include "bsl/BPSecLib_Private.h"
#include "bsl/cose_sc/CoseContext.h"
#include "bsl/default_sc/DefaultSecContext.h"
#include "bsl/default_sc/rfc9173.h"
#include "bsl/dynamic/MLibConfig.h"
#include "bsl/dynamic/SecOperation.h"
#include "bsl/dynamic/SecurityActionSet.h"
#include "bsl/dynamic/Variant.h"
#include "bsl/front/Data.h"
#include "bsl/front/BSLMemory.h"

#include <stdint.h>
"#;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let project_source_dir = PathBuf::from(env::var("BSL_PROJECT_SOURCE_DIR").unwrap_or_else(|_| {
        manifest_dir
            .ancestors()
            .nth(4)
            .expect("sample_pp/rust is under src/bsl/sample_pp")
            .to_string_lossy()
            .to_string()
    }));
    let source_dir = PathBuf::from(
        env::var("BSL_SOURCE_DIR").unwrap_or_else(|_| project_source_dir.join("src").to_string_lossy().to_string()),
    );
    let binary_dir = PathBuf::from(env::var("BSL_BINARY_DIR").unwrap_or_else(|_| {
        let default_cmake_dir = project_source_dir.join("build/src");
        if default_cmake_dir.join("bsl/BSLConfig.h").exists() {
            default_cmake_dir.to_string_lossy().to_string()
        } else {
            source_dir.to_string_lossy().to_string()
        }
    }));

    println!("cargo:rerun-if-env-changed=BSL_PROJECT_SOURCE_DIR");
    println!("cargo:rerun-if-env-changed=BSL_SOURCE_DIR");
    println!("cargo:rerun-if-env-changed=BSL_BINARY_DIR");
    println!("cargo:rerun-if-env-changed=BSL_BINDGEN_INCLUDE_DIRS");
    println!("cargo:rerun-if-changed={}", binary_dir.join("bsl/BSLConfig.h").display());
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("bsl/default_sc/DefaultSecContext.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("bsl/default_sc/rfc9173.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("bsl/cose_sc/CoseContext.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("bsl/dynamic/SecurityAction.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("bsl/dynamic/SecOperation.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("bsl/dynamic/Variant.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("bsl/front/Data.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("bsl/front/BSLMemory.h").display()
    );

    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let bindings = bindgen::Builder::default()
        .header_contents("bsl_sample_pp_bindgen_wrapper.h", BINDGEN_WRAPPER)
        .clang_arg(format!("-I{}", source_dir.display()))
        .clang_arg(format!("-I{}", binary_dir.display()))
        .clang_arg(format!("-I{}", binary_dir.join("bsl").display()))
        .clang_arg(format!("-I{}", project_source_dir.join("deps/mlib").display()))
        .clang_arg(format!("-I{}", project_source_dir.join("deps/QCBOR/inc").display()))
        .clang_args(
            env::var("BSL_BINDGEN_INCLUDE_DIRS")
                .unwrap_or_default()
                .split(':')
                .filter(|dir| !dir.is_empty())
                .map(|dir| format!("-I{}", dir)),
        )
        .allowlist_type("BSL.*")
        .allowlist_type("BP.*")
        .allowlist_type("QCBOR.*")
        .allowlist_type("QCBORE.*")
        .allowlist_type("m_.*")
        .allowlist_type("RFC9173.*")
        .allowlist_type("rfc9173.*")
        .allowlist_function("BSL.*")
        .allowlist_function("BP.*")
        .allowlist_var("BSL.*")
        .allowlist_var("BP.*")
        .allowlist_var("BSLX.*")
        .allowlist_var("RFC9173.*")
        .prepend_enum_name(false)
        .generate_comments(false)
        .wrap_unsafe_ops(true)
        .rust_edition(bindgen::RustEdition::Edition2024)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("unable to generate BSL sample_pp dependency bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("could not write bindings");
}
