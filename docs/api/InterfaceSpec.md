@page BSL Interface Specification
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
This document functions as the AMMOS MiMTAR required interface specificaiton.

Bundle Protocol Security Library (BPSec Lib) Software Interface Specification
=============================================================================

***Prepared By: The Johns Hopkins University Applied Physics Laboratory (JHU/APL)***

**Change Log**
| Revision | Submission Date | Affection Sections or Pages | Change Summary            |
|----------|-----------------|-----------------------------|---------------------------|
| Initial  | 10/2/2024       | All                         | Initial issue of document |



# 1: Document Overview

## 1.1: Identification




| Property                        | Value                               |
|---------------------------------|-------------------------------------|
| Configuration ID (CI)           | 681.2                               |
| Element                         | Multi-Mission Control System (MMCS) |
| Program Set                     | Bundle Protocol Security (BPSec)    |
| Version                         | 0.0                                 |

## 1.2: Purpose

This document describes the software interfaces and APIs necessary to use the BPSec Library (BSL), an implementation of Bundle Protocol Security (BPSec), as specified in the IETF RFC 9172. It is intended for application programmers who plan to use the BSL with their software. The purpose of this document is to enable the reader to access the detailed API documentation, but not to serve as the detailed documentation itself. Therefore, this document is not expected to change between major version updates.

The following portion of Section 1 covers BSL-relevant terminology and other documents/specifications relevant to the Bundle Protocol, Bundle Protocol Security, and the BSL’s implementation thereof.

Section 2 covers miscellaneous information about operating assumptions, including host environment and platform, initialization, and programming language details.

Section 3 provides an overview of the BSL API, which application programmers should use as an introduction to using the BSL. Note that this document does not provide details of individual functions or constants within the BSL. Those may be found in referenced documents including the auto-generated source code documentation.

Finally, the BSL is open-source software whose design and implementation should be expected to evolve in response to operational feedback. As such, this and related documentation may become out-of-date relative to the leading-edge of the BSL code repository. In general, the documentation (including the READMEs, auto-generated API spec, code examples, etc) found in the open-source GitHub repository should be considered the ground source of truth when information appears inconsistent. 

## 1.3: Terminology and Notation


| Term                                | Description |
|-------------------------------------|-------------|
| Abstract Security Block             | Encoded data that goes into the Bundle containing security results.|
| BPSec                               | The security extensions to the Bundle Protocol (IETF RFC 9171), which are specified in RFC 9172.|
| BSL                                 | Bundle Security Layer – the name of this product, which provides a common interface to and implementation of BPSec.|
| BSL Context (Library Context)       | Data structure in the BSL that must be populated by the host application with callbacks and other needed information.|
| Bundle Context                      | A data structure defined in the BSL that contains all contextual information for applying or validating security operations on a given bundle.|
| Bundle Protocol                     | Protocol enabling end-to-end delivery over Delay-Tolerant Networks specified in IETF RFC 9171.|
| CBOR                                | A JSON-like binary encoding scheme used by the Bundle protocol to encode blocks. |
| Dynamic Backend                     | A primary module of the BSL that implements security operations and ancillary operations. Implementations of a backend may be swapped, while the exposed public API remains constant.|
| MLIB                                | A popular third-party open source C programming language library providing dynamic data structures such as vectors, priority queues, and the like.|
| Security Context                    | Library performing actual cryptographic operations as governed by local policy.|
| (Security) Policy Provider          | A library used internally by the BSL to query which security operations need to be applied to a given Bundle. The terms “Security Policy Provider” and “Policy Provider” are used interchangeably.|
| Static Frontend API                 | Defines the software interface between host Bundle Protocol Agents and the underlying security operations implemented in a Dynamic Backend|
| QCBOR                               | QCBOR is a third-party open source library that implements CBOR in the C programming language.|
| Unity                               | In this context Unity is a third-party open-source framework to run unit tests over C and C++ code. Be advised that Unity is a name for a popular graphics programming library, which is unrelated to Unity as referenced here.

## 1.4: References

**Table 1: Applicable JPL Rules Documents**
| Title                | DocID |
|----------------------|-------|
| Software Development | 57653 |

**Table 2: Applicable MGSS Documents**
| Title                                                 | Document Number |
|-------------------------------------------------------|-----------------|
| MGSS Implementation and Maintenance Task Requirements | DOC-001455      |
| BSL Software Req. Doc.                                | DOC-005735      |

**Table 3: Other Applicable Documents**:
| Title                                                            | Document Number                                               |
|------------------------------------------------------------------|---------------------------------------------------------------|
| Bundle Protocol Version 7                                        | IETF RFC 9171                                                 |
| Bundle Protocol Security (BPSec)                                 | IETF RFC 9172                                                 |
| Default Security Contexts for Bundle Protocol Security (BPSec)   | IETF RFC 9173                                                 |
| BSL GitHub Repository                                            | https://github.com/NASA-AMMOS/BSL-private                     |
| BSL Online Documentation                                         | https://github.com/NASA-AMMOS/BSL-private/tree/main/docs      |
| ISO C99 Specification                                            | https://www.iso.org/standard/74528.html                       |
| POSIX 2008 Specification                                         | https://pubs.opengroup.org/onlinepubs/9699919799.2008edition/ |
| NIST FIPS 140 Specification                                      | https://csrc.nist.gov/pubs/fips/140-3/final                   |
| SE Linux Overview                                                | https://www.redhat.com/en/topics/linux/what-is-selinux        |

# 2: Environment

## 2.1: Hardware Characteristics and Limitations

The BSL is regression-tested and targeted primarily toward a RHEL-9 platform on an x86-64 processor. The BSL is written in strict ISO C99 and intentionally developed in a way to maximize cross-platform suitability for many POSIX-consistent targets and speciality hardware, such as VxWorks and RTEMS.

The BSL defines a software interface written in C to maximize suitability for host applications regardless of their choice of programming language.

The BSL is expected to operate on a host with FIPS 140-mode enabled and SE Linux enforcing. Developers must test in this environment otherwise undefined behaviour may occur.


## 2.2: Interface Medium and Characteristics

The BSL is a software library that compiles to a Linux shared or static object, which must be linked to a host binary in order to execute. The BSL does not itself produce and run any independent threads of execution.

Host applications must link to the BSL object files during their build process, according to the instructions and examples located in the BSL wiki page on GitHub. Host applications will call C functions directly to execute BPSec subroutines. If the host application is not programmed in C or C++, then a suitable Foreign Function Interface (FFI) for that specific programming language should be used. Note, the authors of the BSL cannot guarantee the correctness when using BSL with an FFI.


## 2.3: Standards and Protocols

The BSL implements the specifications for Bundle Protocol Security and its default security context, as detailed in RFC 9172 and RFC 9173, respectively.

The stable Frontend API is written compliant to the ISO C99 programming language spec, and will always remain so. The Dynamic Backend is likewise written in ISO C99, though differing implementations of the backend are not subject to this constraint. 

The BSL assumes it is building for a POSIX 2008-consistent operating system.
References for each of these are found in Section 1 of this document.


## 2.4: Software Initialization

There is no specific runtime initialization for the BSL. However, software developers using the BSL in their applications must call certain initialization functions before invoking BSL security operations. Specifically, the host interface must provide function callbacks and registries of security Policy Providers and Security Contexts. However, the BSL does not contain any other specific runtime configuration items required by the host.

# 3: Additional Software Interface Details

## 3.1: Frontend vs Backend

The BSL implementation has two central notional components: The “Frontend API” and the “Dynamic Backend”. This distinction permits the existence of multiple backends that implement BPSec functionality, each potentially tailored to operational settings, to be accessed via a common interface. For example, a Bundle Protocol Agent running in SWaP-constrained hardware may need an implementation using strict memory-management that fits in a small memory footprint, whereas a BPA serving as a Bundle Protocol Router on conventional hardware may choose to use a backend leveraging hardware acceleration and greater access to computing resources. The BSL ships with a default backend, written in C99 with some dynamic data structures, which balances suitability for constrained systems and overall flexibility. 

The “Frontend API” defines the stable public interface for the BSL, which the host application uses to invoke BPSec functionality. The “Frontend API” is mostly abstract, containing forward-declared data structures, function prototypes, and limited compiled artifacts. Application programmers for a BPA generally need to be familiar only with the frontend API – its functions and structures. Adhering to this API permits the BPA to be agnostic to the implementation details of any backend.

The “Dynamic Backend” is the default implementation of a backend implementing the Frontend API and contains the functionality detailed in RFC 9172. It uses the term “Dynamic” since it supports since it permits the use of dynamic data structures with flexible memory consumption (as opposed to statically allocated memory).

Backends may be swapped out with another implementation that implements the front-end API. Since BPSec may be deployed in many types of systems with different resources and different operational environments, there is unlikely to be a one-size-fits-all backend implementation. The backend provided here should be understood as an example and reference for more tailored mission-specific implementations.


## 3.2: Instructions for Building Documentation

The most up-to-date documentation will be found in the BSL’s GitHub page, and the details of any API function or data-structure will likewise be found in the documentation generated from annotations inside the source code (using doxygen). As such, this document will generally avoid API specifics since it these may become obsolete as BSL evolves in response to operational needs.

Instructions to build the documentation using doxygen as HTML (and/or PDF, among other formats) may be found in the README.md file. Assuming a RHEL9 platform, the Linux tool xdg-open may be used to open the index.html found under build/default/docs/doxygen/html/index.html.

The menu on the left-hand side includes this overview, as well as links to the top-level modules in the repository. These include the Frontend API, Dynamic Backend, the default security context, the example Security Policy Provider, and a “mock” BPA required to exercise the Frontend. Delving further into each of these shows the relevant files, functions, and data structures.

Links will be found in Table 3 above.


## 3.3: BSL Modules and Data Structures

As indicated in the prior section, the BSL has four main components. The principal two are the Frontend API and the Dynamic backend. There are two others, being the security policy provider, and the security context.

 * The **Frontend API** defines the software interface between host Bundle Protocol Agents and the underlying security operations implemented in a Dynamic Backend. The API remains an invariant regardless of which backend is selected.
 * The **Dynamic Backend** is an implementation of the BPSec security operations that adheres to the Frontend API. The BSL’s design and implementation facilitate “swapping” backend implementations tailored for mission-specific constraints. The BSL ships with a default backend, which may not be suitable for all operational environments.
 * The **Example Security Policy Provider** is a library used internally by the BSL to query which security operations need to be applied to a given Bundle, and what those security parameters are (such as key, hash type, etc). The BSL provides an example security provider exercising the policy provider interface.
 * The **Example Default Security Contexts** perform the actual cryptographic functionality. The Default Security Context is detailed in RFC 9173. The BSL implements this via the security context interface, and uses OpenSSL as the underlying cryptographic software.

## 3.4: BSL Context Initialization

The BSL requires the existence of a Security Policy Provider (commonly referred to as the “Policy Provider” throughout subsequent documentation), which governs what security actions should be performed upon a particular bundle, and a Security Context, which handles all cryptographic material and safely performs the cryptographic functionality.

An example Policy Provider is included in the repository, as well as an implementation of the Default Security Context (as specified in RFC 9173).

Refer to the doxygen-generated documentation in the repository for the relevant BSL initialization functions, that provision the library with the appropriate policy provider and security context.


## 3.5:  BSL Bundle Lifecycles and Workflos

At each of the four points of contact between the BPA and BSL, the BPA invokes the BSL, which goes on to query the security policy provider, and returns an ordered list of security operations to be performed on the bundle according to local security policy.

The BPA then iterates through this list calling the relevant BSL functions to perform the given security operation. These operations are of two types. The first simply verifies a given security result indicating whether it is successful or a failure reason code, and does not manipulate the Bundle in any way. The second type, indicated by “finalize” in the relevant API function names, either apply a new security Block to the bundle, modify a Block in the bundle, or strip a security block from a Bundle (following its successful verification).

## 3.6: Software Dependencies

The BSL strives to avoid excessive reliance on third-party libraries and a long software supply chain. A few third-party libraries are required, however, to: provide dynamic data structures for this C codebase; provide a unit-test driver; provide a codec for CBOR-encoded Bundle blocks; and provide implementations of cryptographic algorithms. At the time of the Critical Design Review, these third-party open-source libraries respectively are MLib, Unity, QCBOR, and OpenSSL. 

Note that specific library versions are detailed in Release Description Documents (RDD), which is produced with each release of BSL.

| Library Name | Repository Link                            |
|--------------|--------------------------------------------|
| MLIB         | MLib https://github.com/P-p-H-d/mlib       |
| Unity        |  https://github.com/ThrowTheSwitch/Unity   |
| QCBOR        | https://github.com/laurencelundblade/QCBOR |
| OpenSSL      | https://github.com/openssl/openssl         |

