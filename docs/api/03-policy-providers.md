@page policy-providers Policy Provider Topics
<!--
Copyright (c) 2025 The Johns Hopkins University Applied Physics
Laboratory LLC.

This file is part of the Bundle Protocol Security Library (BSL).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This work was performed for the Jet Propulsion Laboratory, California
Institute of Technology, sponsored by the United States Government under
the prime contract 80NM0018D0004 between the Caltech and NASA under
subcontract 1700763.
-->

This page covers the using BSL from the perspective of a developer of a new Policy Provider (PP) for the BSL.

# Policy Provider Callback API {#pp-callback-api}

The BSL dynamic backend declares a set of functions which are delegated to each PP instance and are registered in the backend using the [BSL_PolicyDesc_t](@ref BSL_PolicyDesc_s).
These functions include some bookkeeping of the PP instance itself (associated user data and deinit function).

The operational focus of the PP callbacks are functions used by the BSL to:
 * **Inspect** the contents of a bundle and determine if any security operations need to be performed (as BSL_PolicyDesc_s::query_fn).
   This will likely involve introspecting block-level and field-level data from the bundle via the @ref bpa-callback-api.
 * **Finalize** (handle the conclusion of) any requested security operations (as BSL_PolicyDesc_s::finalize_fn).
   This will likely involve bundle or block manipulation depending upon the success or failure of the operation to execute (by its associated [Security Context](@ref sc-callback-api).
