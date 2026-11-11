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

from _test_util import BundleDestLoc, DataFormat, _TestCase
from test_bpa import TestAgent


class TestSamplePolicy(TestAgent):
    """Test Cases utilizing JSON policy definitions with the Default contexts"""

    def test_source_bib_bcb(self):
        self._single_test(
            _TestCase(
                # A bundle with just the **payload** block
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Bundle with BIB and BCB
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 3, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                policy_config="data/policy_provider_source_test.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
                use_bcb_rng=True,
            )
        )

    def test_source_norule_delete(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [3, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output=r".*<INFO>.* Immediate deletion: reason=12",
                policy_config="data/policy_provider_source_test.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
                use_bcb_rng=True,
            )
        )

    def test_verify_bib_bcb(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [11, 3, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 3, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                policy_config="data/policy_provider_verify_test.json",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
                use_bcb_rng=True,
            )
        )

    def test_accept_bib_bcb(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [11, 3, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="data/policy_provider_accept_test.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
                use_bcb_rng=True,
            )
        )

    def test_multitarget_source_bib(self):
        self._single_test(
            _TestCase(
                input_data="""
                [_
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, << 300 >>],
                    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
                ]
                """,
                expected_output="""
                [_
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [11, 3, 0, 0, <<
                        [2, 1],
                        1,
                        1,
                        [2, [2, 1]],
                        [
                            [1, 7],
                            [3, 0]
                        ],
                        [
                            [
                                [1, h'6A8B78889ABB36F06A2272B88F7FCEAB74FE69B35B4C5F7B737634FF478D9FD800F0797E2CE6AC0F0D413B34C2196E1E777A180CB63FFC33D2761E386177FA78']
                            ],
                            [
                                [1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']
                            ]
                        ]
                    >>],
                    [7, 2, 0, 0, << 300 >>],
                    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
                ]""",
                policy_config="data/multitarget_config/policy_provider_multitarget_source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_multitarget_source_bcb(self):
        self._single_test(
            _TestCase(
                input_data="""
                [_
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, << 300 >>],
                    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
                ]
                """,
                expected_output="""
                [_
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [12, 3, 1, 0, <<
                        [2, 1],
                        2,
                        1,
                        [2, [2, 1]],
                        [
                            [1, h'5477656C7665313231323132'],
                            [2, 1],
                            [4, 0]
                        ],
                        [
                            [[1, h'58CCBAF35A762004BA5B023987FF3FA4']],
                            [[1, h'EFA4B5AC0108E3816C5606479801BC04']]
                        ]
                    >>],
                    [7, 2, 0, 0, h'716D8C'],
                    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
                ]""",
                policy_config="data/multitarget_config/policy_provider_multitarget_source.json",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
                use_bcb_rng=True,
            )
        )

    def test_multitarget_source_bib_correlation_mismatch(self):
        self._single_test(
            _TestCase(
                input_data="""
                [_
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, << 300 >>],
                    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
                ]
                """,
                expected_output=r".*SecOper uses correlation ID 1, but has mismatched parameters",
                policy_config="data/multitarget_config/policy_provider_multitarget_source_correlation_mismatch.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_multitarget_accept_bib(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [7, 2, 0, 0, h'19012C'],
    [11, 3, 0, 0, << [1, 2], 1, 1, [2, [3, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']], [[1, h'6A8B78889ABB36F06A2272B88F7FCEAB74FE69B35B4C5F7B737634FF478D9FD800F0797E2CE6AC0F0D413B34C2196E1E777A180CB63FFC33D2761E386177FA78']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [7, 2, 0, 0, h'19012C'],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="data/multitarget_config/policy_provider_multitarget_accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_multitarget_accept_bcb(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [7, 2, 0, 0, h'11A0E4'],
    [12, 3, 0, 0, << [1, 2], 2, 1, [2, [3, 1]], [[1, h'0C565B2389529A9D91D704D1'], [2, 1], [4, 0]], [[[1, h'2147BB883460EBFDB38BB08D70993594']], [[1, h'EC411F330F06A1E8594160C0267902CC']]] >>],
    [1, 1, 0, 0, h'5AC4A915F715206DAA44FDEF717A3BF0669F2AA068AB1D9EE52215F4BBFB6F94D92F2E']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [7, 2, 0, 0, h'19012C'],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="data/multitarget_config/policy_provider_multitarget_accept.json",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_multitarget_accept_bcb_concat_authtag(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [7, 2, 0, 0, h'11A0E4EC411F330F06A1E8594160C0267902CC'],
    [12, 3, 0, 0, << [1, 2], 2, 1, [2, [3, 1]], [[1, h'0C565B2389529A9D91D704D1'], [2, 1], [4, 0]], [[], []] >>],
    [1, 1, 0, 0, h'5AC4A915F715206DAA44FDEF717A3BF0669F2AA068AB1D9EE52215F4BBFB6F94D92F2E2147BB883460EBFDB38BB08D70993594']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [7, 2, 0, 0, h'19012C'],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="data/multitarget_config/policy_provider_multitarget_accept.json",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_multitarget_verify_bcb_concat_authtag(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [7, 2, 0, 0, h'11A0E4EC411F330F06A1E8594160C0267902CC'],
    [12, 3, 0, 0, << [1, 2], 2, 1, [2, [3, 1]], [[1, h'0C565B2389529A9D91D704D1'], [2, 1], [4, 0]], [[], []] >>],
    [1, 1, 0, 0, h'5AC4A915F715206DAA44FDEF717A3BF0669F2AA068AB1D9EE52215F4BBFB6F94D92F2E2147BB883460EBFDB38BB08D70993594']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 3, 0, 0, << [1, 2], 2, 1, [2, [3, 1]], [[1, h'0C565B2389529A9D91D704D1'], [2, 1], [4, 0]], [[], []] >>],
    [7, 2, 0, 0, h'11A0E4EC411F330F06A1E8594160C0267902CC'],
    [1, 1, 0, 0, h'5AC4A915F715206DAA44FDEF717A3BF0669F2AA068AB1D9EE52215F4BBFB6F94D92F2E2147BB883460EBFDB38BB08D70993594']
]
""",
                policy_config="data/multitarget_config/policy_provider_multitarget_verify.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )
