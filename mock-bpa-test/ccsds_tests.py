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
import yaml
import cbor2
import binascii
from _test_util import _TestCase, _TestSet, DataFormat

# TODO in progress

class _CCSDS_Cases(_TestSet):

    def __init__(self):
        super().__init__()

        s = open("../ccsds_bpsec_redbook_draft_734.5-R-2_requirements_implementation_guide.yaml")
        requirements = yaml.safe_load(s)['requirements']
        for item in requirements:
            if 'tests' not in item.keys():
                print(f'CCSDS | Skipping item {item["item"]}: No tests specified.')
                continue

            for t in item['tests']:
                outcome = t['outcome'].split(' ')[0] == "SUCCESS."
                if outcome:
                    input = t['incoming_bundle']['hex'][2:].replace(" ", "")[:-1]
                    b_input = binascii.unhexlify(input)
                    cbor_input = cbor2.loads(b_input)

                    output = t['outgoing_bundle']['hex'][2:].replace(" ", "")[:-1]
                    b_output = binascii.unhexlify(output)
                    output = cbor2.loads(b_output)
                    output_format = DataFormat.BUNDLEARRAY
                else:
                    try:
                        input = t['incoming_bundle']['hex'][2:].replace(" ", "")[:-1]
                        b_input = binascii.unhexlify(input)
                        cbor_input = cbor2.loads(b_input)
                    except Exception:
                        print(f'CCSDS | Test {t["test"]}: Bundle hex not specified, TODO yaml should be filled in.')
                        continue

                    output = (FAILURE_CODE, 0)
                    output_format = DataFormat.ERR
                    
                self.cases['ccsds_' + str(t['test'])] = _TestCase(
                    input_data = cbor_input,
                    expected_output = output,
                    policy_config = "1", #TODO CRITICAL, 
                    # this will probably require modifying the YAML / creating a Policy JSON config since policies are currently written descriptions
                    
                    expect_success = outcome,
                    is_implemented = True,
                    input_data_format = DataFormat.BUNDLEARRAY,
                    expected_output_format = output_format
                )
                print(f'CCSDS | Adding test {t["test"]}...')
