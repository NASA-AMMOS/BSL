@page security-contexts Security Context Topics
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

This page covers the using BSL from the perspective of a developer of a new Security Context (SC) for the BSL.

# Security Context Callback API {#sc-callback-api}

The BSL dynamic backend declares a set of functions which are delegated to each SC instance and are registered in the backend using the [BSL_SecCtxDesc_t](@ref BSL_SecCtxDesc_s).
These functions include some bookkeeping of the SC instance itself (associated user data and deinit function).

The operational focus of the SC callbacks are functions used by the BSL to:
 * **Validate** the options for a specific security operation associated with the SC (as BSL_SecCtxDesc_s::validate).
 * **Execute** a specific security operation associated with the SC (as BSL_SecCtxDesc_s::execute).
