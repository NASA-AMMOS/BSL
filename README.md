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

# The NASA AMMOS BPSec Library (BSL)

![example workflow](https://github.com/github/docs/actions/workflows/build-test.yml/badge.svg)

The BPSec Library (BSL) is an implementation of *Bundle Protocol Security* as specified in [RFC 9172](https://datatracker.ietf.org/doc/rfc9172/) and [RFC 9173](https://datatracker.ietf.org/doc/rfc9173/), with a flexible architecture enabling ready adaptability to flight or ground systems.

The BSL exposes an interface via C header files (under `src`), and contains an example backend implementing this interface in `src/backend`. The BSL also contains an implementation of the Default Security Context (RFC 9173) under `src/security_context` and a sample policy provider under `src/policy_provider`. Together these form a complete the set of functionality required to execute Bundle Protocol Security.

## Project Organization

The following are the major parts of this project.

**Note.** The BSL API (both Public and Private) lives at the top level `src` directory.
Example concrete modules implementations are found in subdirectories of it.

```
BSL/
├── build.sh             # Top-level build utility script
├── cmake/               # Additional CMake files
├── deps/                # Third-party dependencies
├── docs/                # Doxygen pages and templates
├── mock-bpa-test/       # Full BSL test/example using Mock BPA
├── pkg/                 # Material for building RPMs
├── resources/           # Additional helper util scripts
├── src/                 # Source code, top level is header-only API
├── src/backend          # Implementation of example dynamic backend
├── src/mock_bpa         # Implementation of example Mock BPA
├── src/policy_provider  # Implementation of the example policy provider
├── src/security_context # Implementation of RFC 9173 (Default Sec Context)
└── test/                # Unit tests
```

## Development Requirements

_Note!_ BSL uses **Red Hat Enterprise Linux (RHEL 9)** as the target build environment. Ubuntu is frequently used by developers, but not supported as an official target.

The following should be installable by the system package manager:

_Required: Build and Run Unit Tests_
 * CMake, GCC or Clang, OpenSSL (Development), Ninja Build, Valgrind, Memcheck.

_Optional: To Construct Docs, etc..._
 * Doxygen, Ruby, gcovr (as Python package).

## Building BSL

**Note.** `build.sh` is the BSL general build script, that mostly serves as a wrapper for CMake commands. Most actions to configure, build, and deploy BSL work through this script.
```
# To view available subcommands
./build.sh help
```

To clone submodules, build, and run the unit tests:

```
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

#### Optional Additional Build Targets
Code Coverage
```
./build.sh coverage

# To open coverage report in a browser...
xdg-open build/default/coverage/index.html
```

Doxygen Documentation
```
./build.sh prep -DBUILD_DOCS_API=ON
./build.sh docs

# To open in a browser...
xdg-open build/default/docs/api/html/index.html
```

Note: On earlier versions of CMake (<3.20), `./build.sh check` target may not run correctly.

## Testing with the Mock BPA

The Mock BPA demonstrates how a BPA may interact with the BSL, it is found in `src/mock_bpa`.

Details of the Mock BPA are found in the Doxygen documentation.

#### Mock BPA System Test

These instructions are from CI, and may need to be updated.
```
python3 -m venv venv
source venv/bin/activate
pip install -r mock-bpa-test/requirements.txt
python3 -m pytest mock-bpa-test --capture=no --log-cli-level=debug
```

### Running with Wireshark and Local Sockets

```
wireshark -i lo -f 'port 4556 or port 24556' -k
```

Start the mock BPA with local sockets:
```
./build.sh
./build.sh install
./build.sh run bsl-mock-bpa -u localhost:4556 -r localhost:14556 -o localhost:24556 -a localhost:34556
```

Send a trial bundle from the underlayer, which is taken from Appendix A.1.4 of RFC 9173.
```
echo 9f88070000820282010282028202018202820201820018281a000f4240850b0200005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff | xxd -r -p | socat stdio udp-sendto:localhost:4556,pf=ip6,sourceport=14556 | xxd -p
```
Alternatively for the overlayer app socket use `socat stdio unix-sendto:/tmp/foo.sock` instead.

