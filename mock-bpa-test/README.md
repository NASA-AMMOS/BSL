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
# BSL Mock BPA Test
This directory contains a set of pytest-compatible test fixtures to exercise the Mock BPA.
It will run using `./build.sh run` which will execute with a PATH environment preferring `./testroot/usr/bin` followed by system paths.
This means it can test a local build as well as test the installed RPM packages.

Tests can be logged using Wireshark similar to
```sh
wireshark -i lo -k \
    -f 'udp port 4556 or udp port 14556 or udp port 24556 or udp port 34556' \
    -d 'udp.port==14556,bundle' -d 'udp.port==24556,bundle' -d 'udp.port==34556,bundle' \
    -Y bpv7
```