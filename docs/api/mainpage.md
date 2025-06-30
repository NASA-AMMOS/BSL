<!--
Copyright (c) 2024 The Johns Hopkins University Applied Physics
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
@mainpage Introduction

This documentation is for the detailed BPSec Library (BSL) application programming interface (API) in the C language.
This is an implementation of RFC 9172 @cite rfc9172 functionality and RFC 9173 @cite rfc9173 default security contexts.

For details about installation, maintenance, and compile-time use of the BSL, see the _BSL Product Guide_ @cite bsl_prod_guide.
For details about higher-level run-time use patterns, see the _BSL User Guide_ @cite bsl_user_guide.

There is more technical detail about the BSL architecture in the [Background](Background.md) page.

# Getting Started with the API

Each runtime instance of the BSL is isolated for thread safety within a host-specific struct referenced by a @ref BSL_LibCtx_t pointer.

The runtime instance is used by the BPA via the BSL _service interface_ to process bundles at each of the following four security interaction points within the BPA's bundle workflow.
When invoked from the BPA, all BSL activities will occur within the context of a single bundle which is referenced by a @ref BSL_BundleCtx_t pointer.

Details of how the BSL processing order relates to other BPA processing of bundles along the BPA's workflow are left to the BPA integration.

* After bundle creation from an application source, indicated by ::BSL_POLICYLOCATION_APPIN
* Before bundle delivery to an application destination, indicated by ::BSL_POLICYLOCATION_APPOUT
* After bundle reception via a CLA, indicated by ::BSL_POLICYLOCATION_CLIN
* Before bundle forwarding via a CLA, indicated by ::BSL_POLICYLOCATION_CLOUT

These are shown for a notional BPA in the diagram below, where each edge indicates one of the four interaction points listed above.

@dot "BPA Interaction Points" width=500pt
digraph bpa_interaction {
    rankdir=LR;
    node [shape=record, fontname=Helvetica, fontsize=12];

    process [ label="Bundle Dispatch\nand Forwarding" ];
    appin [ label="Application\nSource" ];
    appout [ label="Application\nDelivery" ];
    clin [ label="CLA\nReception" ];
    clout [ label="CLA\nForwarding" ];

    appin -> process [ label="BSL Call" ];
    process -> appout [ label="BSL Call" ];
    clin -> process [ label="BSL Call" ];
    process -> clout [ label="BSL Call" ];
}
@enddot


@defgroup frontend Frontend
@brief Files in the Frontend library of the BSL.

This provides the abstract APIs used for the BSL service interface and APIs used by Policy Provider implementations and Security Context implementations.


@defgroup backend_dyn Dynamic Backend
@brief Files in the Dynamic Backend library of the BSL.

This is the concrete implementation of a backend using dynamic heap-allocated containers and registries.
It uses POSIX APIs to provide necessary Host functions for the BSL, and OpenSSL APIs to provide crypto functions for the BSL.


@defgroup example_pp Example Policy Provider
@brief Implementation of a simple rule-based policy provider.

This group contains files used by the Example Policy Provider library included with the BSL.


@defgroup example_security_context Default Security Contexts
@brief Implementation of the default security contexts using the BSL crypto API.

This group contains files used by the Default Security Contexts library included with the BSL.

@defgroup mock_bpa Example/Mock BP Agent
@brief Files used in the Mock BPA used for testing.

The Mock BPA performs whole-bundle encoding and decoding (CODEC) functions, but no other stateful bundle processing.
