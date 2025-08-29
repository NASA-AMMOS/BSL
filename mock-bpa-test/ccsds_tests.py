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

policyset_json_format = '''{{ 
    "policyrule_set": [
        {}
    ]
}}
'''

policyrule_json_format = '''{{
    "policyrule": {{
    "desc": "{desc}",
    "filter": {{
        "rule_id": "{rule_id}",
        "role": "{role}",
        "tgt": {target},
        "loc": "clin",
        "sc_id": {sec_ctx}
    }},
    "spec": {{
        "sc_id": {sec_ctx},
        "sc_parms": [
            {sc_params}
        ]
    }},
    "_temp_not_ion_spec_policy_action_on_fail": "{policy_act}"
    }}
}}'''

sc_param_json_format = '''{{  
    "id": "{param_id}",
    "value": "{value}"
}} '''

class _CCSDS_Cases(_TestSet):

    def __init__(self):
        super().__init__()

        ccsds_test_dir = 'mock-bpa-test/ccsds_json/'

        s = open("mock-bpa-test/ccsds_bpsec_redbook_requirements_modified.yaml")
        requirements = yaml.safe_load(s)['requirements']
        for item in requirements:
            if 'tests' not in item.keys():
                #print(f'CCSDS | Item {item["item"]}: Skipping item - No test(s) specified.')
                continue
            
            for t in item['tests']:
                if not t['working']:
                    continue

                outcome = t['outcome'].split(' ')[0] == "SUCCESS."
                if outcome:
                    input = t['incoming_bundle']['hex'][2:].replace(" ", "")[:-1]
                    b_input = binascii.unhexlify(input)
                    cbor_input = cbor2.loads(b_input)
                    input_format = DataFormat.BUNDLEARRAY

                    output = t['outgoing_bundle']['hex'][2:].replace(" ", "")[:-1]
                    b_output = binascii.unhexlify(output)
                    output = cbor2.loads(b_output)
                    output_format = DataFormat.BUNDLEARRAY
                else:
                    try:
                        input = t['incoming_bundle']['hex'][2:].replace(" ", "")[:-1]
                        b_input = binascii.unhexlify(input)
                        cbor_input = cbor2.loads(b_input)
                        input_format = DataFormat.BUNDLEARRAY

                    except Exception:
                        print(f'CCSDS | Test {t["test"]}: Bundle hex not specified.')
                        continue

                    output_format=DataFormat.ERR

                bib_param_key_good = sc_param_json_format.format(param_id='key_name', value='9100')
                bib_param_key_bad = sc_param_json_format.format(param_id='key_name', value='9102')
                bib_param_sha = sc_param_json_format.format(param_id='sha_variant', value='7')
                bib_param_scope = sc_param_json_format.format(param_id='scope_flags', value='0')

                bcb_param_key_good = sc_param_json_format.format(param_id='key_name', value='9102')
                bcb_param_key_bad = sc_param_json_format.format(param_id='key_name', value='9100')
                bcb_param_aes = sc_param_json_format.format(param_id='aes_variant', value='1')
                bcb_param_scope = sc_param_json_format.format(param_id='aad_scope', value='0')

                rules_json = []
                policy_rules=t['rules']
                success = True
                for i, r in enumerate(policy_rules):

                    #       sec block
                    #          |   sec role
                    #          |      |     tgt blk type
                    #          |      |      |  good key?
                    #          |      |      |  |
                    #          v      v      v  v
                    #       b[i|c]b_[a|s|v]_\d_\d
                    policy_desc = r['description'].split('_')
                    if len(policy_desc) != 4:
                        print(f'CCSDS | Test {t["test"]}: Policyrule {i} misconfigured.')
                        success = False
                        break

                    if policy_desc[3] == 0:
                        bib_params = f'{bib_param_key_bad},{bib_param_sha},{bib_param_scope}'
                        bcb_params = f'{bcb_param_key_bad},{bcb_param_aes},{bcb_param_scope}'
                    else:
                        bib_params = f'{bib_param_key_good},{bib_param_sha},{bib_param_scope}'
                        bcb_params = f'{bcb_param_key_good},{bcb_param_aes},{bcb_param_scope}'

                    sec_ctx = -1
                    params = ''
                    if policy_desc[0] == 'bcb':
                        sec_ctx = 2
                        params = bcb_params
                    elif policy_desc[0] == 'bib':
                        sec_ctx = 1
                        params = bib_params
                    else:
                        print(f'CCSDS | Test {t["test"]}: Policyrule {i} sec ctx misconfigured.')
                        success = False
                        break

                    sec_role = policy_desc[1]
                    if sec_role != 's' and sec_role != 'a' and sec_role != 'v':
                        print(f'CCSDS | Test {t["test"]}: Policyrule {i} sec role misconfigured.')
                        success = False
                        break

                    target = policy_desc[2]

                    pr = policyrule_json_format.format(
                        desc=r['description'],
                        rule_id=str(i),
                        role=sec_role,
                        target=target,
                        sec_ctx=sec_ctx,
                        policy_act='delete_bundle',
                        sc_params=params
                    )
                    rules_json.append(pr)

                if not success:
                    continue

                policyrules = ','.join(rules_json)
                final_json = policyset_json_format.format(policyrules)
                finame = ccsds_test_dir + f"{t['test']}.json"
                with open(finame, "w") as f:
                    f.write(final_json)

                self.cases['ccsds_' + str(t['test'])] = _TestCase(
                    input_data = cbor_input,
                    # Python raw strings only work as literals apparently
                    expected_output = output if (output_format == DataFormat.BUNDLEARRAY) else r".*Delete bundle due to failed security operation",
                    policy_config = finame,                    
                    is_working = True,
                    input_data_format = input_format,
                    expected_output_format = output_format
                )
                print(f'CCSDS | Test {t["test"]}: Appending case.')
