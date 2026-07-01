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
''' Test Cases utilizing JSON policy definitions with the COSE context
'''
import contextlib
import json
import logging
import os
import tempfile
from typing import Any, Dict
import unittest
from _test_util import _TestCase, DataFormat, BundleDestLoc
from test_bpa import TestAgent

OWNPATH = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger(__name__)

EXAMPLE_A_NO_SEC = '''\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [1, 1, 0, 2, << "hello" >>, h'4EC359D2']
]
'''
''' Example A input bundle with no security blocks '''
EXAMPLE_A_1_WITH_BIB = '''\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [11, 2, 0, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[17, << [<< {1: 6} >>, {4: 'ExampleA.1'}, null, h'EC8260A38A1A00FEF2CD4AAE063F50F01C5645E84C6C4893CA895EED44EF60A5F50F9ADF5CC5654499B881E589637805'] >>]]] >>],
    [1, 1, 0, 2, << "hello" >>, h'4EC359D2']
]
'''
''' Bundle with BIB over target #1, adjusted sec block to #2 '''
EXAMPLE_A_4_WITH_BCB = '''\
[_
    [7, 0, 2, [1, "//dst/svc"], [1, "//src/svc"], [1, "//src/"], [813110400000, 0], 1000000, h'82A081C9'],
    [12, 2, 1, 0, << [1], 3, 1, [1, "//src/"], [[5, {0: 1, -1: 1}]], [[[16, << [<< {1: 3} >>, {4: h'4578616D706C65412E34', 6: h'484A'}, null] >>]]] >>],
    [1, 1, 0, 2, h'1FD25F64A2EEE2FF1A1AB29812BA221874380974C13B', h'2086C017']
]
'''
''' Bundle with BIB over target #1, adjusted sec block to #2 with flags 0x1'''

@contextlib.contextmanager
def sc_config_modifier(orig: str, modify: Dict[str, Any]):
    ''' A context for modifying baseline configurations '''
    with tempfile.NamedTemporaryFile('w+', suffix=".json") as polfile:
        with open(os.path.join(OWNPATH, orig), 'r') as infile:
            poldata = json.load(infile)

        params: dict = poldata["policyrule_set"][0]["policyrule"]["spec"]["sc_parms"]
        LOGGER.debug('Original params:\n%s', params)
        params |= modify
        LOGGER.debug('Modified params:\n%s', params)

        json.dump(poldata, polfile)
        polfile.flush()
        yield polfile


class TestCoseScJsonPolicy(TestAgent):

    def test_exampleA_1_Mac0_source(self):
        self._single_test(_TestCase(
            input_data=EXAMPLE_A_NO_SEC,
            expected_output=EXAMPLE_A_1_WITH_BIB,
            sec_src_eid='dtn://src/',
            policy_config='data/cose-sc/policy-exA.1-source.json',
            bundle_dest_loc=BundleDestLoc.APPIN,
            key_set="data/cose-sc/keyset-1.cbordiag",
            is_working=True,
            input_data_format=DataFormat.CBORDIAG,
            expected_output_format=DataFormat.CBORDIAG
        ))

    def test_exampleA_1_Mac0_acceptor_valid(self):
        self._single_test(_TestCase(
            input_data=EXAMPLE_A_1_WITH_BIB,
            expected_output=EXAMPLE_A_NO_SEC,
            sec_src_eid='dtn://src/',
            policy_config='data/cose-sc/policy-exA.1-accept.json',
            bundle_dest_loc=BundleDestLoc.APPIN,
            key_set="data/cose-sc/keyset-1.cbordiag",
            is_working=True,
            input_data_format=DataFormat.CBORDIAG,
            expected_output_format=DataFormat.CBORDIAG
        ))

    def test_exampleA_1_Mac0_acceptor_valid_strict_aad_scope(self):
        with sc_config_modifier('data/cose-sc/policy-exA.1-accept.json', {"aad_scope": {'0': 1, '-1': 1}}) as polfile:
            self._single_test(_TestCase(
                input_data=EXAMPLE_A_1_WITH_BIB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid='dtn://src/',
                policy_config=polfile.name,
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                is_working=True,
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG
            ))

    def test_exampleA_1_Mac0_acceptor_failure_wrong_key(self):
        with sc_config_modifier('data/cose-sc/policy-exA.1-accept.json', {"key_id": "ExampleA.5"}) as polfile:
            self._single_test(_TestCase(
                input_data=EXAMPLE_A_1_WITH_BIB,
                expected_output='.* Not implemented',
                sec_src_eid='dtn://src/',
                policy_config=polfile.name,
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                is_working=True,
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR
            ))

    def test_exampleA_1_Mac0_acceptor_failure_key_missing(self):
        with sc_config_modifier('data/cose-sc/policy-exA.1-accept.json', {"key_id": "missing"}) as polfile:
            self._single_test(_TestCase(
                input_data=EXAMPLE_A_1_WITH_BIB,
                expected_output='.* Unknown key ID',
                sec_src_eid='dtn://src/',
                policy_config=polfile.name,
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                is_working=True,
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR
            ))

    def test_exampleA_1_Mac0_acceptor_failure_aad_mismatch(self):
        with sc_config_modifier('data/cose-sc/policy-exA.1-accept.json', {"aad_scope": {'0': 1, '-1': 2}}) as polfile:
            self._single_test(_TestCase(
                input_data=EXAMPLE_A_1_WITH_BIB,
                expected_output='.* Mismatch of AAD Scope parameter',
                sec_src_eid='dtn://src/',
                policy_config=polfile.name,
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                is_working=True,
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR
            ))

    def test_exampleA_4_Enc0_source(self):
        self._single_test(_TestCase(
            input_data=EXAMPLE_A_NO_SEC,
            expected_output=EXAMPLE_A_4_WITH_BCB,
            sec_src_eid='dtn://src/',
            policy_config='data/cose-sc/policy-exA.4-source.json',
            bundle_dest_loc=BundleDestLoc.APPIN,
            key_set="data/cose-sc/keyset-1.cbordiag",
            is_working=True,
            input_data_format=DataFormat.CBORDIAG,
            expected_output_format=DataFormat.CBORDIAG
        ))

    def test_exampleA_4_Enc0_acceptor_valid(self):
        self._single_test(_TestCase(
            input_data=EXAMPLE_A_4_WITH_BCB,
            expected_output=EXAMPLE_A_NO_SEC,
            sec_src_eid='dtn://src/',
            policy_config='data/cose-sc/policy-exA.4-accept.json',
            bundle_dest_loc=BundleDestLoc.APPIN,
            key_set="data/cose-sc/keyset-1.cbordiag",
            is_working=True,
            input_data_format=DataFormat.CBORDIAG,
            expected_output_format=DataFormat.CBORDIAG
        ))

    def test_exampleA_4_Enc0_acceptor_valid_strict_aad_scope(self):
        with sc_config_modifier('data/cose-sc/policy-exA.4-accept.json', {"aad_scope": {'0': 1, '-1': 1}}) as polfile:
            self._single_test(_TestCase(
                input_data=EXAMPLE_A_4_WITH_BCB,
                expected_output=EXAMPLE_A_NO_SEC,
                sec_src_eid='dtn://src/',
                policy_config=polfile.name,
                bundle_dest_loc=BundleDestLoc.APPIN,
                key_set="data/cose-sc/keyset-1.cbordiag",
                is_working=True,
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG
            ))

    def test_ccsds_interop_Mac0_source(self):
        self._single_test(_TestCase(
            input_data='''\
[_
    [7, 0, 1, [2, [4, 9]], [2, [1, 1]], [2, [1, 1]], [819280839425, 0], 8640000000, h'179D'],
    [6, 4, 1, 0, << [2, [1, 0]] >>],
    [10, 3, 1, 0, << [3, 1] >>],
    [7, 2, 1, 0, << 63000 >>],
    [1, 1, 0, 0, 'hello']
]
''',
            # Bundle with BIB over target #2
            expected_output='''\
[_
    [7, 0, 1, [2, [4, 9]], [2, [1, 1]], [2, [1, 1]], [819280839425, 0], 8640000000, h'179D'],
    [11, 5, 0, 0, << [2], 3, 1, [2, [1, 0]], [[5, {0: 1, -1: 1}]], [[[17, << [<< {1: 6} >>, {4: 'ExampleA.1'}, null, h'8C552E8B1FDC5021394961090323EB8A15CD0D451A843219BDB501583EF4773A632AABFC17551C081CD919FD7DEFD105'] >>]]] >>],
    [6, 4, 1, 0, << [2, [1, 0]] >>],
    [10, 3, 1, 0, << [3, 1] >>],
    [7, 2, 1, 0, << 63000 >>],
    [1, 1, 0, 0, 'hello']]
''',
            sec_src_eid='ipn:1.0',
            policy_config='data/cose-sc/policy-interop-A.1.json',
            bundle_dest_loc=BundleDestLoc.APPIN,
            key_set="data/cose-sc/keyset-1.cbordiag",
            is_working=True,
            input_data_format=DataFormat.CBORDIAG,
            expected_output_format=DataFormat.CBORDIAG
        ))

    @unittest.expectedFailure
    def test_ccsds_interop_Mac_KEK_source(self):
        self._single_test(_TestCase(
            input_data='''\
[_
    [7, 0, 1, [2, [4, 9]], [2, [1, 1]], [2, [1, 1]], [819280839425, 0], 8640000000, h'179D'],
    [6, 4, 1, 0, << [2, [1, 0]] >>],
    [10, 3, 1, 0, << [3, 1] >>],
    [7, 2, 1, 0, << 63000 >>],
    [1, 1, 0, 0, 'hello']
]
''',
            # Bundle with BIB over target #1
            expected_output='''\
[_
    [7, 0, 1, [2, [4, 9]], [2, [1, 1]], [2, [1, 1]], [819280839425, 0], 8640000000, h'179D'],
    [11, 5, 0, 0, << [1], 3, 1, [2, [1, 0]], [[5, {0: 1, -1: 1}]], [[[97, << [<< {1: 6} >>, {}, null, h'9AC51C5D72F96E44099C521298691C087ECF7DA8EC99A9CFB8A6FCB5A44A4B054FF1669289F7EAF7719EBBF95FBABB3A', [['', {1: -5, 4: 'ExampleA.5'}, h'442B1844E188743A7569623749A0FBE09C8540EEEC72EE419744EAA8E70B8FFAD13FDE7C1FADCB4EDC68A641A6191683C43D87990F579775']]] >>]]] >>],
    [6, 4, 1, 0, << [2, [1, 0]] >>],
    [10, 3, 1, 0, << [3, 1] >>],
    [7, 2, 1, 0, << 63000 >>],
    [1, 1, 0, 0, 'hello']]
''',
            sec_src_eid='ipn:1.0',
            policy_config='data/cose-sc/policy-interop-A.5.json',
            bundle_dest_loc=BundleDestLoc.APPIN,
            key_set="data/cose-sc/keyset-1.cbordiag",
            is_working=True,
            input_data_format=DataFormat.CBORDIAG,
            expected_output_format=DataFormat.CBORDIAG
        ))
