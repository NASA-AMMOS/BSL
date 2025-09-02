from _test_util import _TestCase, _TestSet, DataFormat

# Test Cases utilizing JSON policy definitions
class _JSONPolicyTests(_TestSet):

    def __init__(self):
        super().__init__()

        self.cases['json_source_bib_bcb'] = (_TestCase(
            # A bundle with just the **payload** block
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Bundle with BIB and BCB
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [12, 3, 1, 0, bytes.fromhex('8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')]
            ],
            policy_config='mock-bpa-test/policy_provider_test.json',
            is_working=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY          
        ))
