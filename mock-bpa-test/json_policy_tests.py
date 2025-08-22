from _test_util import _TestCase, _TestSet, DataFormat
from _test_util import NO_OUTPUT, FAILURE_CODE, DELETION


# Test Cases specified by the Requirements Document
class _JSONPolicyTests(_TestSet):

    def __init__(self):
        super().__init__()

        self.cases['json_source_bib'] = (_TestCase(
            # A bundle with just the **payload** block
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Bundle with additional BIB
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            policy_config='policy_provider_test.json',
            is_working=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY          
        ))
