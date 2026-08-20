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
"""Test Cases utilizing JSON policy definitions with the default contexts"""

import logging
import os
import unittest

from _test_util import BundleDestLoc, DataFormat, _TestCase, sc_config_modifier
from test_bpa import TestAgent

OWNPATH = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger(__name__)

EXAMPLE_A_NO_SEC = """\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
"""
""" Example A input bundle with no security blocks """

EXAMPLE_A_1_WITH_BIB = """\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
"""
""" Bundle with BIB over target #1, adjusted sec block to #2 """

EXAMPLE_A_2_WITH_BCB = """\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
"""
""" Bundle with BCB over target #1, adjusted sec block to #2 with flags 0x1"""

EXAMPLE_EMPTY_PAYLOAD = """\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'']
]
"""
""" Example A input bundle adjusted to have empty payload """

EXAMPLE_EMPTY_PAYLOAD_WITH_BIB = """\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'97F2168D91EA3BC9BE02FDC225AD2DCF70DD823BA4E13E11E599D8ACFB364502014F25220DFA5FFFDFF98C0C1BE7B235CA53A0B09B2F0D1776220F2E7A8DF372']]] >>],
    [1, 1, 0, 0, h'']
]
"""
""" Bundle with BIB over target #1 """

EXAMPLE_EMPTY_PAYLOAD_WITH_BCB = """\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'']
]
"""
""" Bundle with BCB over target #1 """


class TestBibHmacSha(TestAgent):
    def test_exampleA_1_source(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_NO_SEC,
                expected_output=EXAMPLE_A_1_WITH_BIB,
                sec_src_eid="ipn:2.1",
                policy_config="data/default-scs/policy-exA.1-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/default-scs/keyset-1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_1_acceptor_valid_match(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_1_WITH_BIB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="ipn:1.0",
                policy_config="data/default-scs/policy-exA.1-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/default-scs/keyset-1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_1_acceptor_failure_key_mismatch(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/default-scs/policy-exA.1-accept.json"),
            modify={"key_name": "ExampleA.2"},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_1_WITH_BIB,
                    expected_output=".*<ERROR>.* Auth tag result mismatched",
                    sec_src_eid="ipn:1.0",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/default-scs/keyset-1.json",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.ERR,
                )
            )

    def test_exampleA_1_acceptor_failure_sha_variant(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/default-scs/policy-exA.1-accept.json"),
            modify={"sha_variant": 6},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_1_WITH_BIB,
                    expected_output=".*<ERROR>.* SHA variant mismatch, needed 6 got 7",
                    sec_src_eid="ipn:1.0",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/default-scs/keyset-1.json",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.ERR,
                )
            )

    @unittest.skip("the operation still proceeds after mismatch")
    def test_exampleA_1_acceptor_failure_aad_mismatch(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/default-scs/policy-exA.1-accept.json"),
            modify={"scope_flags": 0x1},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_1_WITH_BIB,
                    expected_output=".*<WARNING>.* IPPT Scope mismatch, needed 1 got 0",
                    sec_src_eid="ipn:1.0",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/default-scs/keyset-1.json",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.ERR,
                )
            )

    def test_empty_target_source(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_EMPTY_PAYLOAD,
                expected_output=EXAMPLE_EMPTY_PAYLOAD_WITH_BIB,
                sec_src_eid="ipn:2.1",
                policy_config="data/default-scs/policy-exA.1-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/default-scs/keyset-1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )


class TestBcbAesGcm(TestAgent):
    def test_exampleA_2_source(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_NO_SEC,
                expected_output=None,  # non-deterministic BTSD
                sec_src_eid="ipn:2.1",
                policy_config="data/default-scs/policy-exA.2-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/default-scs/keyset-1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ANYCBOR,
            )
        )

    def test_exampleA_2_acceptor_valid_match(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_A_2_WITH_BCB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid="ipn:1.0",
                policy_config="data/default-scs/policy-exA.2-accept.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/default-scs/keyset-1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_exampleA_2_acceptor_failure_key_mismatch(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/default-scs/policy-exA.2-accept.json"),
            modify={"key_name": "ExampleA.1"},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_2_WITH_BCB,
                    expected_output=".*<ERROR>.* Failed to unwrap AES key",
                    sec_src_eid="ipn:1.0",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/default-scs/keyset-1.json",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.ERR,
                )
            )

    def test_exampleA_2_acceptor_failure_aes_variant(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/default-scs/policy-exA.2-accept.json"),
            modify={"aes_variant": 2},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_2_WITH_BCB,
                    expected_output=".*<ERROR>.* AES variant mismatch, needed 2 got 1",
                    sec_src_eid="ipn:1.0",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/default-scs/keyset-1.json",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.ERR,
                )
            )

    @unittest.skip("the operation still proceeds after mismatch")
    def test_exampleA_2_acceptor_failure_aad_mismatch(self):
        with sc_config_modifier(
            orig=os.path.join(OWNPATH, "data/default-scs/policy-exA.2-accept.json"),
            modify={"aad_scope": 0x1},
        ) as polfile_path:
            self._single_test(
                _TestCase(
                    input_data=EXAMPLE_A_2_WITH_BCB,
                    expected_output=".*<WARNING>.* AAD Scope mismatch, needed 1 got 0",
                    sec_src_eid="ipn:1.0",
                    policy_config=polfile_path,
                    bundle_dest_loc=BundleDestLoc.APPIN,
                    key_set="data/default-scs/keyset-1.json",
                    input_data_format=DataFormat.CBORDIAG,
                    expected_output_format=DataFormat.ERR,
                )
            )

    def test_empty_target_source(self):
        self._single_test(
            _TestCase(
                input_data=EXAMPLE_EMPTY_PAYLOAD,
                expected_output=None,  # non-deterministic BTSD
                sec_src_eid="ipn:2.1",
                policy_config="data/default-scs/policy-exA.2-cek-source.json",
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/default-scs/keyset-1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ANYCBOR,
            )
        )
