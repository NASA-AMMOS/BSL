@page examples-and-mocks Example PPs, SCs, and Mock BPA
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

This page discusses example Policy Providers (PPs), Security Contexts (SCs), and a mock BPA used for testing the BSL proper.
The BSL proper is associated with the @ref frontend and @ref backend_dyn groups.

# Example Policy Providers {#example-pps}

The unit tests of the BSL use, where necessary, very minimal implementations of a PP to set up preconditons for test cases.

The Mock BPA uses a PP implementation tailored to meet the needs of the BSL acceptance tests.
This PP uses a set of bit fields within an integer program argument to control policy options; the fields are documented on ::bsl_mock_policy_configuration_t.
It also allows multiple integer policy values to be configured in a single running Mock BPA.
This PP is registered and used by the @ref mock-bpa for many BSL testing cases.

A more full-featured draft PP maintained as part of the BSL source is based on the JSON-encoded policy structure used in the earlier ION implementation of the Default Security Contexts @cite ion-bpsec-policy.
This PP parses an ION-Like JSON structure to configure policy rules within a running Mock BPA. See the _BSL User Guide_ @cite bsl_user_guide for details on specific JSON structure and attributes.
This PP is registered and used by the @ref mock-bpa for many BSL testing cases.

Sources related to these example PPs are associated with the @ref example_pp group.

# Example Default Security Contexts {#example-default-scs}

The two Default Security Contexts defined in RFC 9173 @cite rfc9173 offer minimal, interoperable, and pre-shared-key-focused integrity and confidentiality operations.

An implementation of these two SCs is maintained as part of the BSL source and uses the BSL crypto library as an interface to the OpenSSL library @cite lib:openssl from the host OS.
These SCs are registered and used by the @ref mock-bpa for BSL testing.

Sources related to these example SCs are associated with the @ref example_security_context group.

# Mock BPA {#mock-bpa}

The BSL source repository contains a "Mock BPA" application which performs a minimal amount of BPv7 PDU processing and exercises the BSL service interface on those bundles.
The Mock BPA uses an un-framed UDPCL-like interface for its underlayer and also its application overlayer for ease of integration with a larger test fixture.

The Mock BPA is limited to a single registered endpoint, and does no other handling normally required by RFC 9171 @cite rfc9171. So for this reason it is not a true BPA and must not be treated as one.

Upon startup, the Mock BPA registers a single [ION-based Example Policy Provider](@ref example-pps) and the two [example Default Security Contexts](@ref example-default-scs).

Sources related to the Mock BPA are associated with the @ref mock_bpa group.

## Policy Management

The policies used by the Mock BPA's example policy providers can be provided with two different methods.

### Policy Bit Fields

This policy provider initializes its policy using a set of bit fields within an integer program argument to control policy options; the fields are documented on ::bsl_mock_policy_configuration_t. 
The bit fields should be comma-separated, and passed to the Mock BPA with the `-p` command line option (see [Command Line Options](#command-line-options)).

### ION-Like JSON-Encoded Policy

This policy provider initializes its policy using ION-like JSON-encoded structures @cite ion-bpsec-policy. 
The path to the JSON file should be passed to the Mock BPA with the `-j` command line option (see [Command Line Options](#command-line-options)).

## Key Management

The keys used by the example SCs registered in the Mock BPA's Cryptographic Library instance are obtained from a file using the JSON Web Key (JWK) format of RFC 7517 @cite rfc7517.

The implementation to support these SCs only handles symmetric keys and only the minimal header parameters needed for key ID ("kid") and key material itself.

## Command Line Options

See the Mock BPA man page for more details

| Option    | Description                                                                                                                       |
|--------   |------------------------------------                                                                                               |
| `-h`      | Get command help information and exit.                                                                                            |
| `-o`      | Overlayer local address-and-port to bind to.                                                                                      |
| `-a`      | Overlayer application address-and-port to send to and receive from.                                                               |
| `-u`      | Underlayer local address-and-port to bind to.                                                                                     |
| `-r`      | Underlayer router address-and-port to send to and receive from.                                                                   |
| `-e`      | The endpoint ID of the local applicaiton which is registered.                                                                     |
| `-s`      | The endpoint ID of the local security source used to handle BPSec.                                                                |
| `-p`      | The comma-seperated bitfields representing policies to initialize Mock BPA with.                                                  |
| `-j`      | The path to a ION-Like Policy JSON-encoded policy structure file containing policies to initialize Mock BPA with.                 |
| `-k`      | The path to a JSON Web Key (JWK) formatted file containing keys to register with the Mock BPA’s Cryptographic Library instance.   |
