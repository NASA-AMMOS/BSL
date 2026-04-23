#
# Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
# Laboratory LLC.
#
# This file is part of the Bundle Protocol Security Library (BSL).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This work was performed for the Jet Propulsion Laboratory, California
# Institute of Technology, sponsored by the United States Government under
# the prime contract 80NM0018D0004 between the Caltech and NASA under
# subcontract 1700763.
#
from enum import IntEnum, unique
from dataclasses import dataclass
from typing import Any


@unique
class DataFormat(IntEnum):
    BUNDLEARRAY = 0
    HEX = 1
    ERR = 2
    NONE = 3


@unique
class BundleDestLoc(IntEnum):
    APPIN = 0
    CLIN = 1


@dataclass
# Holds a simple test case
class _TestCase:
    # list representation of bundle
    input_data: Any

    # either list representation of expected output bundle OR a string to search log output for match
    expected_output: DataFormat

    # decimal digit representing uint32 for policy configuration OR path to JSON-encoded ION-like policy rules
    policy_config: str

    # path to JWK-encoded key set
    key_set: str

    # data format of input
    input_data_format: DataFormat

    # data format of output
    expected_output_format: DataFormat

    # True if test working (can be removed once all tests are working)
    is_working: bool = True

    # destination location of the bundle
    bundle_dest_loc: BundleDestLoc = BundleDestLoc.CLIN

    # If true, test will use custom rng callback for BCB testing
    use_bcb_rng: bool = False