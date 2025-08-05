<<<<<<< HEAD
=======
#
# Copyright (c) 2025 The Johns Hopkins University Applied Physics
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
>>>>>>> main
from enum import Enum

class DataFormat(Enum):
    BUNDLEARRAY=0
    HEX=1
    ERR=2
    NONE=3

# "structure" to hold a simple test case
class _TestCase:
    '''
    @param input_data list representation of bundle | TODO hex option / fully hex?
    @param expected_output either list representation of expected output bundle OR tuple for outcome (FAILURE_CODE, N), (NO_OUTPUT, N), etc.
    @param policy_config decimal digit representing uint32 for policy configuration | TODO switch to a hex string?
    @param impl - boolean, true if test is implemented, false if not (placeholder for empty test fixtures)
    @param success - boolean, true if input bundle is expected to have an output bundle, false if error/no output
    '''
    def __init__(self, input_data, expected_output, policy_config, 
<<<<<<< HEAD
                 is_implemented : bool, expect_success: bool, 
=======
                 is_implemented : bool, is_working: bool, expect_success: bool, 
>>>>>>> main
                 input_data_format : DataFormat, expected_output_format : DataFormat):
        self.input_data = input_data
        self.expected_output = expected_output
        self.policy_config = policy_config

        # can be removed once all tests are implemeneted
        self.is_implemented = is_implemented

<<<<<<< HEAD
=======
        # can be removed once all tests are wworking
        self.is_working = is_working

>>>>>>> main
        # true if test expected to succeed (return output bundle with no errors)
        self.expect_success = expect_success

        self.input_data_format = input_data_format
        self.expected_output_format = expected_output_format


class _TestSet:
    def __init__(self):
        self.cases = {}

NO_OUTPUT = 0
FAILURE_CODE = -1
DELETION = -2