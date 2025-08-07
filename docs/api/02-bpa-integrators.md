@page bpa-integrators BPA Integrator Topics
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

This page covers the using BSL from the perspective of a BPA developer integrating the BSL through its _service interface_.

# BPA--BSL Interactions

A BPA interacts with the BSL through two distinct interfaces:

 * A **[service interface](@ref bsl-service-api)** provided by the BSL, which is called by the BPA when security processing of a bundle is needed
 * A **[callback interface](@ref bpa-callback-api)** provided by the BPA

@dot "BPA--BSL Interfaces" width=500pt
digraph bpa_interfaces {
    rankdir=TB;
    node [shape=record, fontname=Helvetica, fontsize=12];

    bpa [ label="BPA" ];
    bsl [ label="BSL" ];

    bpa -> bsl [ xlabel="BSL Service API" ];
    bsl -> bpa [ xlabel="BPA Callback API" ];
}
@enddot

# BSL Service API {#bsl-service-api}

Each runtime instance of the BSL is isolated for thread safety within a host-specific struct referenced by a [BSL_LibCtx_t](@ref BSL_LibCtx_s) pointer.

The runtime instance is used by the BPA via the BSL _service interface_ to process bundles at each of the following four security interaction points within the BPA's bundle workflow.
When invoked from the BPA, all BSL activities will occur within the context of a single bundle which is referenced by a ::BSL_BundleRef_t pointer.

Details of how the BSL processing order relates to other BPA processing of bundles along the BPA's workflow are left to the BPA integration.

* After bundle **transmission** from an application source, indicated by ::BSL_POLICYLOCATION_APPIN
* Before bundle **delivery** to an application destination, indicated by ::BSL_POLICYLOCATION_APPOUT
* After bundle **reception** via a CLA, indicated by ::BSL_POLICYLOCATION_CLIN
* Before bundle **forwarding** via a CLA, indicated by ::BSL_POLICYLOCATION_CLOUT

These are shown for a notional BPA in the diagram below, where each edge indicates one of the four interaction points listed above.

@dot "BPA Interaction Points" width=500pt
digraph bpa_interaction {
    rankdir=LR;
    node [shape=record, fontname=Helvetica, fontsize=12];

    process [ label="Bundle Dispatch\nand Forwarding" ];
    appin [ label="Application\nTransmission" ];
    appout [ label="Application\nDelivery" ];
    clin [ label="CLA\nReception" ];
    clout [ label="CLA\nForwarding" ];

    appin -> process [ label="BSL Call" ];
    process -> appout [ label="BSL Call" ];
    clin -> process [ label="BSL Call" ];
    process -> clout [ label="BSL Call" ];
}
@enddot

# BPA Callback API {#bpa-callback-api}

Separate from the API used to call into the BSL to initiate securit processing, the BSL relies on specific functions provided by the BPA to do its normal processing.
Some of these functions are for introspecting and manipulating specific bundle or block contents, others are for encoding and decoding EID and EID Pattern values.

The BSL dynamic backend declares a set of functions which are delegated to the BPA, which are registered in the dynamic backend using the ::BSL_HostDescriptors_t struct and the BSL_HostDescriptors_Set() function.
