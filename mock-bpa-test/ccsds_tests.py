import yaml
import cbor2
import binascii
from _test_util import _TestCase, _TestSet
from _test_util import * 

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
                    cbor_output = cbor2.loads(b_output)
                else:
                    try:
                        input = t['incoming_bundle']['hex'][2:].replace(" ", "")[:-1]
                        b_input = binascii.unhexlify(input)
                        cbor_input = cbor2.loads(b_input)
                    except Exception:
                        print(f'CCSDS | Test {t["test"]}: Bundle hex not specified, TODO yaml should be filled in.')
                        continue

                    cbor_output = (FAILURE_CODE, 0)
                    
                self.cases['ccsds_' + str(t['test'])] = _TestCase(
                    input_data = cbor_input,
                    expected_output = cbor_output,
                    policy_config = "1", #TODO
                    expect_success = outcome,
                    is_implemented = True,
                    input_data_format = "BUNDLEARRAY",
                    expected_output_format= "BUNDLEARRAY"
                )
                print(f'CCSDS | Adding test {t["test"]}...')
