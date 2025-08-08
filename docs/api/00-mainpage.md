@mainpage Introduction
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

This documentation is for the detailed BPSec Library (BSL) application programming interface (API) in the C language.
This is an implementation of RFC 9172 @cite rfc9172 functionality and RFC 9173 @cite rfc9173 default security contexts.

For details about installation, maintenance, and compile-time use of the BSL, see the _BSL Product Guide_ @cite bsl_prod_guide.
For details about higher-level run-time use patterns, see the _BSL User Guide_ @cite bsl_user_guide.

# Library Architecture {#bsl-arch}

The BSL as a whole is separated into two primary layers of implementation: an API-centric abstract _Frontend_ library and a host-binding concrete _Backend_ library.

The Frontend library provides the service API for the BSL to be called by its associated [BPA integration](@ref bpa-integrators) and for stable public APIs used by [Policy Provider implementations](@ref policy-providers) and [Security Context implementations](@ref security-contexts).
The Backend library implements forward-declared structs and functions from the Frontend using specific concrete data containers, algorithms, _etc._

The BSL source repository also contains @ref example-pps and @ref example-default-scs to actually exercise the BSL during testing, and a @ref mock-bpa which allows as-built integration testing of the BSL using a pseudo-daemon process.

@dot
digraph example {
    node [shape=record, fontname=Helvetica, fontsize=10];

    frontend [ label="Frontend" ];
    backend [ label=<<i>Backend</i>> ];
    frontend -> backend [ dir=back ];

    host [ label="Host" ];
    bpa [ label="BPA" ];
    crypto [ label="Crypto\nFunctions" ];
    reg_pol [ label="Policy\nRegistry" ];
    reg_sc [ label="Security Context\nRegistry" ];
    backend -> host [ arrowhead="open", style="dashed" ];
    backend -> bpa [ arrowhead="open", style="dashed" ];
    backend -> crypto [ arrowhead="open", style="dashed" ];
    backend -> reg_pol [ arrowhead="open", style="dashed" ];
    backend -> reg_sc [ arrowhead="open", style="dashed" ];
}
@enddot

The BSL comes with a @ref frontend and a @ref backend_dyn implementation which uses heap-allocated, dynamically-sized data structures and run-time registration capabilities.
For a more constrained (_e.g._, flight software) environment an alternative backend could be implemented with fixed-size data containers and constant-time registry lookup algorithms.

Along with these libraries are also two integration extensions: an _Example Policy_ module and a _Default Security Contexts_ module.
Together these use the abstract Frontend and populate the otherwise empty Dynamic Backend registries to create an out-of-the-box usable BPSec implementation.

# Dependencies

The BSL is written for the C99 language @cite ISO:9899:1999 excluding any compiler-specific extensions.

The Dynamic Backend relies on the POSIX.1-2008 @cite IEEE:1003.1-2008 standard for operating system abstraction, and M*LIB @cite lib:mlib for heap-allocated data containers.

The example default security contexts use the OpenSSL library @cite lib:openssl for all cryptographic functions, including random number generation.
This allows these security contexts to be FIPS-140 @cite NIST:FIPS-140-3 compliant.

BSL unit tests use the Unity library @cite lib:unity for test execution and assertions.


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
