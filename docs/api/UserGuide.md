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

# User Guide (BPA Developer)

This page covers the using BPSecLib from the perspective of the **Application Programmer**, or more specifically, the BPA developer.

## BPA Interaction

 - Notes.

---

This page discusses information about the structure of the BSL but not its actual APIs.

# Library Architecture

The BSL as a whole is separated into two primary layers of implementation: an API-centric abstract _Frontend_ library and a host-binding concrete _Backend_ library.

The Frontend library provides the service API for the BSL to be called by its associated BPA as needed and for stable public APIs used by Policy Provider implementations and Security Context implementations.
The Backend library implements forward-declared structs and functions from the Frontend using specific concrete data containers, algorithms, etc.

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

The BSL comes with a @ref frontend and a @ref backend_dyn implementation which uses heap-allocated, dynamially-sized data structures and run-time registration capabilities.
For a more constrained (_e.g._, flight software) environment an alternative backend could be implemented with fixed-size data containers and constant-time registry lookup algorithms.

Along with these libraries are also two integration extensions: an _Example Policy_ module and a _Default Security Contexts_ module.
Together these use the abstract Frontend and populate the otherwise empty Dynamic Backend registries to create an out-of-the-box usable BPSec implementation.

# Dependencies

The BSL is written for the C99 language @cite ISO:9899:1999 excluding any compiler-specific extensions.

The Dynamic Backend relies on the POSIX.1-2008 @cite IEEE:1003.1-2008 standard for operating system abstraction, and M*LIB @cite lib:mlib for heap-allocated data containers.

BSL unit tests use the Unity library @cite lib:unity for test execution and assertions.
