<!--
Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
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

# The NASA AMMOS BPSec Library (BSL)

The BPSec Library (BSL) is an implementation of *Bundle Protocol Security* as specified in [RFC 9172](https://datatracker.ietf.org/doc/rfc9172/) and [RFC 9173](https://datatracker.ietf.org/doc/rfc9173/), with a flexible architecture enabling ready adaptability to flight or ground systems.

The BSL exposes an interface via C header files (under `src`), and contains an example backend implementing this interface in `src/backend`. The BSL also contains an implementation of the Default Security Context (RFC 9173) under `src/security_context` and a sample policy provider under `src/policy_provider`. Together these form a complete the set of functionality required to execute Bundle Protocol Security.

## Project Organization

The following are the major parts of this project.

```sh
BSL/
├── build.sh             # Top-level build utility script
├── cmake/               # Additional CMake files
├── deps/                # Third-party dependencies
├── docs/                # Doxygen pages and templates
├── pkg/                 # Material for building RPMs and pkg-config
├── resources/           # Additional helper util scripts
├── src/                 # Source code, top level is header-only API
├── src/front            # Implementation of BSL frontend
├── src/dynamic          # Implementation of dynamic backend
├── src/sample_pp        # Implementation of the example policy provider
├── src/default_sc       # Implementation of Default Security Contexts (RFC 9173)
├── src/cose_sc          # Implementation of COSE Context
├── src/crypto           # Implementation of BSL crypto library and key store interface
├── src/mock_bpa         # Implementation of example Mock BPA
├── test/                # Unit tests
├── mock-bpa-test/       # Full BSL test/example using Mock BPA
└── lib-user-test/       # Test an installation of the BSL for building
```

## Development Requirements

> [!NOTE]
> BSL uses **Red Hat Enterprise Linux (RHEL 9)** as the target build environment.
> Ubuntu is frequently used by developers, and for CI jobs, but not supported as an official target.

The following should be installable by the system package manager:

_Required: Build and Run Unit Tests_
 * CMake, GCC or Clang, OpenSSL (Development), Ninja Build, Valgrind, Memcheck, Ruby, jansson-devel.

_Optional: To Construct Docs, etc..._
 * Doxygen, gcovr (as Python package), graphviz, plantuml, texlive-bibtex, asciidoctor.

## Building BSL

The top `build.sh` is the BSL general build script, that mostly serves as a wrapper for CMake commands.
Most actions to configure, build, and deploy BSL work through this script.

To view available subcommands of the script:
```sh
./build.sh help
```

To clone submodules, build, and run the unit tests:

```sh
# Clone dependencies
git submodule update --init --recursive

# Build dependencies
./build.sh deps

# Prepare build environment
./build.sh prep

# Build the software
./build.sh

# Run unit tests
./build.sh check
```

This will take about a minute to build and run the unit tests, there should be 100% success.

> [!NOTE]
> On earlier versions of CMake (<3.20), `./build.sh check` target may not run correctly.

#### Optional Additional Build Targets

Code Coverage

```sh
./build.sh coverage
```

> [!NOTE]
> The coverage target requires that the build prepare stage was run with the CLI flag `-DBUILD_COVERAGE=ON`:
> ```
> ./build.sh prep -DBUILD_COVERAGE=ON
> ```
> For a full list of optional build flags, see [section 3.4.1 of the BSL product guide](https://nasa-ammos.github.io/BSL-docs/product-guide/html/index.html#sec-proc-build-devel-cmake).

The output HTML can be opened in a browser using:
```sh
xdg-open build/default/coverage-html/index.html
```

Doxygen Documentation
```sh
./build.sh prep -DBUILD_DOCS_API=ON
./build.sh docs
```

The output HTML can be opened in a browser using:
```sh
xdg-open build/default/docs/api/html/index.html
```

To check for misspelling in the Doxygen output use the following, substituting the word/phrase you are looking for in the grep command
```sh
xmlstarlet tr build/default/docs/api/xml/combine.xslt build/default/docs/api/xml/index.xml | xmlstarlet tr docs/api/spellcheck.xsl | cat -n | grep -E 'bsl'
```

## Installing BSL

After building, the BSL libraries, headers, and build support files (CMake and pkg-config) can be installed using:
```sh
./build.sh install
```

> [!NOTE]
> The default install script uses environment `DESTDIR=testroot` and `PREFIX=/usr` which installs files under `./testroot/usr/...` paths.
> This allows installing without special permissions on the host.
> Alternatively, the install can be used with different environment such as `DESTDIR=/` to install to system paths.

After install, a trial executable which simply links against the installed BSL using pkg-config discovery can be tested using:
```sh
./build.sh check-install
```

## Testing with the Mock BPA

The Mock BPA demonstrates how a BPA may interact with the BSL, it is found in `src/mock_bpa`.

Details of the Mock BPA are found in the Doxygen documentation.

#### Mock BPA System Test

To execute the Mock BPA tests of the BSL libraries as-built, first prepare a Pythong virtualenv using:
```sh
python3 -m venv venv
source venv/bin/activate
pip install -r mock-bpa-test/requirements.txt
```

Then execute the test suite using:
```sh
python3 -m pytest mock-bpa-test --log-cli-level=info
```

### Running with Wireshark and Local UDP transport

The Mock BPA uses local UDP datagram transport.
This relies on the fact the the loopback device will have a large MTU to avoid the need for BP PDU segmentation.

The UDP ports can be monitored using stock Wireshark with the following command line:
```sh
wireshark -i lo -k \
    -f 'udp port 4556 or udp port 14556 or udp port 24556 or udp port 34556' \
    -d 'udp.port==14556,bundle' -d 'udp.port==24556,bundle' -d 'udp.port==34556,bundle' \
    -Y bpv7
```

Start the mock BPA with local sockets:
```sh
./build.sh
./build.sh install
./build.sh run \
    bsl-mock-bpa -u localhost:4556 -r localhost:14556 -o localhost:24556 -a localhost:34556
```

Send a trial bundle from the underlayer, which is taken from Appendix A.1.4 of RFC 9173.
```sh
echo 9f88070000820282010282028202018202820201820018281a000f4240850b0200005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff | xxd -r -p | socat stdio udp-sendto:localhost:4556,pf=ip6,sourceport=14556 | xxd -p
```
Alternatively for the overlayer app socket use `socat stdio udp-sendto:localhost:24556,pf=ip6,sourceport=34556` instead.
