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
import pytest

from _test_util import BundleDestLoc, DataFormat, _TestCase
from test_bpa import TestAgent


class TestSamplePolicy(TestAgent):
    """Test Cases utilizing JSON policy definitions with the Default contexts"""

    def test_source_bib_bcb(self):
        self._single_test(
            _TestCase(
                # A bundle with just the **payload** block
                input_data=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                # Bundle with BIB and BCB
                expected_output=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [
                        12,
                        3,
                        1,
                        0,
                        bytes.fromhex(
                            "8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04"
                        ),
                    ],
                    [
                        11,
                        2,
                        0,
                        0,
                        bytes.fromhex(
                            "810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1"
                        ),
                    ],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a"
                        ),
                    ],
                ],
                policy_config="data/policy_provider_source_test.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.BUNDLEARRAY,
                expected_output_format=DataFormat.BUNDLEARRAY,
                use_bcb_rng=True,
            )
        )

    def test_source_norule_delete(self):
        self._single_test(
            _TestCase(
                input_data=[
                    [7, 0, 0, [2, [3, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                expected_output=r".*<INFO>.* Immediate deletion: reason=12",
                policy_config="data/policy_provider_source_test.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.BUNDLEARRAY,
                expected_output_format=DataFormat.ERR,
                use_bcb_rng=True,
            )
        )

    def test_verify_bib_bcb(self):
        self._single_test(
            _TestCase(
                input_data=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [
                        12,
                        2,
                        1,
                        0,
                        bytes.fromhex(
                            "8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04"
                        ),
                    ],
                    [
                        11,
                        3,
                        0,
                        0,
                        bytes.fromhex(
                            "810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1"
                        ),
                    ],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a"
                        ),
                    ],
                ],
                expected_output=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [
                        11,
                        3,
                        0,
                        0,
                        bytes.fromhex(
                            "810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1"
                        ),
                    ],
                    [
                        12,
                        2,
                        1,
                        0,
                        bytes.fromhex(
                            "8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04"
                        ),
                    ],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a"
                        ),
                    ],
                ],
                policy_config="data/policy_provider_verify_test.json",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.BUNDLEARRAY,
                expected_output_format=DataFormat.BUNDLEARRAY,
                use_bcb_rng=True,
            )
        )

    def test_accept_bib_bcb(self):
        self._single_test(
            _TestCase(
                input_data=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [
                        12,
                        2,
                        1,
                        0,
                        bytes.fromhex(
                            "8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04"
                        ),
                    ],
                    [
                        11,
                        3,
                        0,
                        0,
                        bytes.fromhex(
                            "810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1"
                        ),
                    ],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a"
                        ),
                    ],
                ],
                expected_output=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                policy_config="data/policy_provider_accept_test.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.BUNDLEARRAY,
                expected_output_format=DataFormat.BUNDLEARRAY,
                use_bcb_rng=True,
            )
        )

    @pytest.mark.skip(reason="policy not configured")
    def test_multitarget_source_bib(self):
        self._single_test(
            _TestCase(
                input_data=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, bytes.fromhex("19012C")],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                expected_output=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, bytes.fromhex("19012C")],
                    [
                        11,
                        3,
                        0,
                        0,
                        bytes.fromhex(
                            "82010201018202820301828201078203008281820158403BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E181820158406A8B78889ABB36F06A2272B88F7FCEAB74FE69B35B4C5F7B737634FF478D9FD800F0797E2CE6AC0F0D413B34C2196E1E777A180CB63FFC33D2761E386177FA78"
                        ),
                    ],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                policy_config="data/policy_provider_multitarget_source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.BUNDLEARRAY,
                expected_output_format=DataFormat.BUNDLEARRAY,
            )
        )

    @pytest.mark.skip(reason="policy not configured")
    def test_multitarget_source_bcb(self):
        self._single_test(
            _TestCase(
                input_data=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, bytes.fromhex("19012C")],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                expected_output=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, bytes.fromhex("19012C")],
                    [
                        11,
                        3,
                        0,
                        0,
                        bytes.fromhex(
                            "82010201018202820301828201078203008281820158403BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E181820158406A8B78889ABB36F06A2272B88F7FCEAB74FE69B35B4C5F7B737634FF478D9FD800F0797E2CE6AC0F0D413B34C2196E1E777A180CB63FFC33D2761E386177FA78"
                        ),
                    ],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                policy_config="data/policy_provider_multitarget_source.json",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.BUNDLEARRAY,
                expected_output_format=DataFormat.BUNDLEARRAY,
            )
        )

    def test_multitarget_accept_bib(self):
        self._single_test(
            _TestCase(
                input_data=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, bytes.fromhex("19012C")],
                    [
                        11,
                        3,
                        0,
                        0,
                        bytes.fromhex(
                            "82010201018202820301828201078203008281820158403BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E181820158406A8B78889ABB36F06A2272B88F7FCEAB74FE69B35B4C5F7B737634FF478D9FD800F0797E2CE6AC0F0D413B34C2196E1E777A180CB63FFC33D2761E386177FA78"
                        ),
                    ],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                expected_output=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, bytes.fromhex("19012C")],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                policy_config="data/policy_provider_multitarget_accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.BUNDLEARRAY,
                expected_output_format=DataFormat.BUNDLEARRAY,
            )
        )

    def test_multitarget_accept_bcb(self):
        self._single_test(
            _TestCase(
                input_data=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, bytes.fromhex("11A0E4")],
                    [
                        12,
                        3,
                        0,
                        0,
                        bytes.fromhex(
                            "820102020182028203018382014C0C565B2389529A9D91D704D182020182040082818201502147BB883460EBFDB38BB08D7099359481820150EC411F330F06A1E8594160C0267902CC"
                        ),
                    ],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "5AC4A915F715206DAA44FDEF717A3BF0669F2AA068AB1D9EE52215F4BBFB6F94D92F2E"
                        ),
                    ],
                ],
                expected_output=[
                    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                    [7, 2, 0, 0, bytes.fromhex("19012C")],
                    [
                        1,
                        1,
                        0,
                        0,
                        bytes.fromhex(
                            "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164"
                        ),
                    ],
                ],
                policy_config="data/policy_provider_multitarget_accept.json",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.BUNDLEARRAY,
                expected_output_format=DataFormat.BUNDLEARRAY,
            )
        )
