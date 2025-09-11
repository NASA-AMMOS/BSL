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
from enum import Enum

class DataFormat(Enum):
    BUNDLEARRAY=0
    HEX=1
    ERR=2
    NONE=3

# "structure" to hold a simple test case
class _TestCase:
    '''
    @param input_data: list representation of bundle
    @param expected_output: either list representation of expected output bundle OR a string to search log output for match 
    @param policy_config: decimal digit representing uint32 for policy configuration OR path to JSON-encoded ION-like policy rules
    @param key_set: path to JWK-encoded key set
    @param is_working: True if test working
    @param input/output_data_format: data format of input/output
    '''
    def __init__(self, input_data, expected_output : DataFormat, policy_config : str, key_set : str, is_working: bool, 
                 input_data_format : DataFormat, expected_output_format : DataFormat):
        self.input_data = input_data
        self.expected_output = expected_output
        self.policy_config = policy_config
        self.key_set = key_set

        # can be removed once all tests are working
        self.is_working = is_working

        self.input_data_format = input_data_format
        self.expected_output_format = expected_output_format
