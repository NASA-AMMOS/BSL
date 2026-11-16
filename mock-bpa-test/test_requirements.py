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

# Test Cases specified by the Requirements Document

# Note about BSL_20:
# The language implies that BSL should generate bundle status reports per policy. This is a responsibility of the BPA, not BSL.
# This requriment is satisfied by the reason code interface, present in all Mock BPA tests.

# Note about BSL_66:
# Many failure test cases parse logs successfully to determine correct failure mode.
# This satisfies the requirement.


class TestRequirements(TestAgent):
    # BSL_2
    # Deterministic Processing Order
    # The purpose of this test case is to verify that BSL shall impose a deterministic processing order for all security blocks.
    # BSL_4, BSL_18 explicitly satisfied by this fixture per Test Spec
    def test_BSL_02(self):
        self._single_test(
            _TestCase(
                # A bundle with BIB and BCB both targeting the **payload** block, policy to accept both the blocks
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 3, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                # A bundle with just the **payload** block
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x1A6,0x1A7",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_3
    # Security Block Inclusion
    # The purpose of this test case is to verify that the BSL shall construct security blocks for inclusion in a bundle.
    #
    # BSL_5 Unit Test informally satisfied by this fixture
    def test_BSL_03(self):
        self._single_test(
            _TestCase(
                # A bundle with just the **payload** block
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Bundle with additional BIB
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x04",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_7
    # Removing Security Operations
    # The purpose of this test case is to verify that the BSL can remove security operations from a bundle.
    #
    # BSL_8, BSL_9 Unit Tests informally satisfied by this fixture
    # BSL_16 explicitly satisfied by BSL_8 per Test Spec
    def test_BSL_07(self):
        self._single_test(
            _TestCase(
                # A bundle with a BIB targeting the **payload** block
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # A bundle with just the **payload** block
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0xA6",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_12
    # Encode BTSD
    # The purpose of this test case is to verify that the BSL can encode the BTSD produced for a security block in compliance with RFC 9172 encodings.
    def test_BSL_12(self):
        self._single_test(
            _TestCase(
                # A bundle with just the primary block
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Bundle with additional BIB
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x04",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_13
    # Decode BTSD
    # The purpose of this test case is to verify that the BSL can decode the BTSD of an RFC 9172 encoded security block.
    def test_BSL_13(self):
        self._single_test(
            _TestCase(
                # A bundle with a BIB targeting the primary block
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Identical bundle output
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # policy_config = BIB_VERIFIER,
                policy_config="0x66",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_14
    # Node Security Role
    # The purpose of this test case is to verify that the BSL shall determine what security role (if any) the local node shall have for a given security operation.
    #
    # Input:
    #       Four bundles each with a BIB targeting the primary block, policy for each option of:
    #       1. Don't care
    #       2. Source a new BIB
    #       3. Verify a BIB
    #       4. Accept a BIB
    # Output:
    #       Four bundles corresponding with:
    #       1. Identical output
    #       2. Additional BIB
    #       3. Identical output with log showing verification
    #       4. Remove BIB
    #
    # BSL_15 explicitly satisfied by this fixture per Test Spec
    def test_BSL_14a(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [0], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'5D9BDD1E2F043CF971588111F2FE1B847666CFACB7FB403C2468EF92A8EC93DF80B41620DF5BC639D0C355E1CCE6217E17D3B8C5560EDC14ABA3D005196B046E']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [0], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'5D9BDD1E2F043CF971588111F2FE1B847666CFACB7FB403C2468EF92A8EC93DF80B41620DF5BC639D0C355E1CCE6217E17D3B8C5560EDC14ABA3D005196B046E']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x2A0",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_BSL_14b(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [0], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'5D9BDD1E2F043CF971588111F2FE1B847666CFACB7FB403C2468EF92A8EC93DF80B41620DF5BC639D0C355E1CCE6217E17D3B8C5560EDC14ABA3D005196B046E']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 3, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [11, 2, 0, 0, << [0], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'5D9BDD1E2F043CF971588111F2FE1B847666CFACB7FB403C2468EF92A8EC93DF80B41620DF5BC639D0C355E1CCE6217E17D3B8C5560EDC14ABA3D005196B046E']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x04",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # 14c) need logs to show verification

    def test_BSL_14c(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [0], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'5D9BDD1E2F043CF971588111F2FE1B847666CFACB7FB403C2468EF92A8EC93DF80B41620DF5BC639D0C355E1CCE6217E17D3B8C5560EDC14ABA3D005196B046E']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [0], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'5D9BDD1E2F043CF971588111F2FE1B847666CFACB7FB403C2468EF92A8EC93DF80B41620DF5BC639D0C355E1CCE6217E17D3B8C5560EDC14ABA3D005196B046E']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                #
                # policy_config = BIB_VERIFIER,
                policy_config="0x62",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_BSL_14d(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [0], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'5D9BDD1E2F043CF971588111F2FE1B847666CFACB7FB403C2468EF92A8EC93DF80B41620DF5BC639D0C355E1CCE6217E17D3B8C5560EDC14ABA3D005196B046E']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0xA2",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_17
    # BPA Deleting Block
    # The purpose of this test case is to verify that the BSL can request that a BPA delete a security target block when required by policy.
    #
    # Verify that the BSL can request that a BPA delete a security target block when required by policy.
    def test_BSL_17(self):
        self._single_test(
            _TestCase(
                # Bundle with a BIB targeting a private-use extension block (type 192).
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [192, 2, 0, 0, h'19012C'],
    [11, 3, 0, 0, << [2], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'FFFF78889ABB36F06A2272B88F7FCEAB74FE69B35B4C5F7B737634FF478D9FD800F0797E2CE6AC0F0D413B34C2196E1E777A180CB63FFC33D2761E386177FA78']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Bundle with removed target block
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 3, 0, 0, << [2], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'FFFF78889ABB36F06A2272B88F7FCEAB74FE69B35B4C5F7B737634FF478D9FD800F0797E2CE6AC0F0D413B34C2196E1E777A180CB63FFC33D2761E386177FA78']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # BIB verifier, CLIN, private-use target, drop target on failure.
                policy_config="0x5A",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_19
    # BPA Deleting Bundle
    # The purpose of this test case is verify that the BSL can request that the BPA delete a bundle when required by policy.
    #
    # 19) need logs to show deletion
    #
    # BSL_42 Unit Test informally satisfied by this fixture
    def test_BSL_19(self):
        self._single_test(
            _TestCase(
                # Bundle with a BIB targeting primary block
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [0], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'5D9BDD1E2F043CF971588111F2FE1B847666CFACB7FB403C2468EF92DDA8EC93DF80B41620DF5BC6C355E1CCE6217E17D3B8C5560EDC14ABA3D005196B046E00']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # No output because it was deleted, logs to indicate deletion.
                expected_output=r".*Delete bundle due to failed security operation",
                policy_config="0x62",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    # BSL_23
    # RFC Compliant Cryptographs
    # The purpose of this test case is to verify that the BSL can alter the contents of non-security blocks to incorporate cryptographic outputs in accordance with RFC 9173.
    #
    # The BIB and BCB test vectors from RFC 9173 demonstrate altering security blocks.
    # The test takes the bundle provided by the unit test (content from RFC 9173) and confirms that after
    # the security operation has been applied, the bundle's blocks match the output described in the test vector.
    #
    # repeat of BSL_2
    def test_BSL_23(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 3, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                # A bundle with just the **payload** block
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x1A6,0x1A7",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_24
    # Security Block Result Fields
    # The purpose of this test case is to verify that the BSL can place cryptographic material in security block security result fields in accordance with RFC 9172 and RFC 9173.
    def test_BSL_24(self):
        self._single_test(
            _TestCase(
                # CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Test that following the given BIB operation from Appendix A, the encoded bundle equals the final bundle
                # in the test vector Appendix A.1.4. This shows the cryptographic results were encoded correctly.
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x04",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_26
    # Retrieving Key Parameters
    # The purpose of this test case is verify that the BSL can retrieve key-related parameters required by key-based security contexts.
    def test_BSL_26(self):
        self._single_test(
            _TestCase(
                # CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Satisfied by validation for SSF-4-0, as performing the security operations must assemble key material.
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x04",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_27
    # Supporting Security Contents
    # The purpose of this test case is to verify that the BSL can support the security contexts identified in RFC 9173.
    #
    # 2 tests:
    #       CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3 (for BIB).
    #       Second input is CBOR provided in Appendix A2 for BCB https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.2
    # Test that for both BIB-protected and BCB-protected Bundle, the expected results match the final result.
    # This shows that they implement the security context of RFC9173 in Appendix A1 and A2.
    #
    # BSL_25 explicitly satisfied by this fixture per Test Spec
    def test_BSL_27a(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x04",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_BSL_27b(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                policy_config="0x105",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
                use_bcb_rng=True,
            )
        )

    # BSL_28
    # Supporting BCB AES GCM
    # The purpose of this test case is to verify that the BSL can support the use of the BCB-AES-GCM default security context [RFC 9173] for BCB-confidentiality security operations.
    # This is the first half of the validation for SSF-4-0
    # repeat of bsl_27b
    #
    # BSL_11 Unit Test informally satisfied by this fixture
    def test_BSL_28(self):
        self._single_test(
            _TestCase(
                # Input is CBOR provided in Appendix A2 for BCB https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.2
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                policy_config="0x105",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
                use_bcb_rng=True,
            )
        )

    # BSL_29
    # Supporting BIB HMAC SHA
    # The purpose of this test case is to verify that the BSL can support the use of the BIB-HMAC-SHA default security context [RFC 9173] for bib-integrity security operations.
    #
    # repeat bsl_27a
    def test_BSL_29(self):
        self._single_test(
            _TestCase(
                # CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3 (for BIB)
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x04",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_33
    # Reason Code 8
    # The purpose of this test case is to verify that the BSL has the ability to inform the BPA that a block is unintelligible using Reason Code 8 as defined in RFC 9171.
    def test_BSL_33a(self):
        self._single_test(
            _TestCase(
                # Using the Bundle from RFC 9173 Appendix A1.4, change the bytes of the BIB header to be be all zeros (thus not a valid CBOR array).
                # 81010101820282020182820107820300 -> 00000000000000000000000000000000
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 4, 0, h'000000000000000000000000000000008181820158403BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1'],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Confirm that the query fails and deletes with Reason Code 8
                expected_output=r".*<ERROR>.*Failed to cache security, not querying policy",
                # Execute as a BIB acceptor.
                policy_config="0xA6",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    def test_BSL_33b(self):
        self._single_test(
            _TestCase(
                # Using the Bundle from RFC 9173 Appendix A1.4, change the bytes of the BIB header to be be all zeros (thus not a valid CBOR array).
                # 81010101820282020182820107820300 -> 00000000000000000000000000000000
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 16, 0, h'000000000000000000000000000000008181820158403BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1'],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Confirm that the operations fails
                expected_output=r".*<ERROR>.*No secop found targeting block number 1",
                # Execute as a BIB acceptor.
                policy_config="0xA6",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    # BSL_37
    # Interface Failure
    # The purpose of this test case is verify that the BSL can report on the failure of any interface to perform a requested operation.
    #
    # 37) need logs to show error
    def test_BSL_37(self):
        self._single_test(
            _TestCase(
                # Using the Bundle from RFC 9173 Appendix A1.4, change the the target to non-existant block number 3
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [3], 1, 1, [2, [2, 1]], [[1, 7], [3, h'0000']], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Ensure that the host interface returns an error code (since the block does not exist). Confirm that a log indicating this error is created.
                expected_output=r".*Deleting bundle due to block target num 1 security failure",
                policy_config="0x66",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    # BSL_38
    # Processing Error
    # The purpose of this test case is to verify that the BSL can cease processing related security operations when there is a processing error associated with those operations.
    #
    # 38) need logs to show new further sec option processed
    #
    # BSL_36 Unit Test informally satisfied by this fixture
    def test_BSL_38(self):
        self._single_test(
            _TestCase(
                # Using the bundle created from RFC 9173 Appendix A.2.4. Change the first 10 bytes of the encrypted payload (BTSD of block 1) to be all zeroes.
                # This will cause decryption to fail.
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 3, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'000000000000000000009C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                # The security operation will return an error code indicating failure. Additionally, using the telemetry counters and logs,
                # confirm that no further security operation processing was taken (specifically, no BIB operations should be seen).
                expected_output=r".*Failed to perform cryptographic action",
                policy_config="0x1A6,0x1A7",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.ERR,
            )
        )

    # BSL_43
    # Query Existing Block Types
    # The purpose of this test case is to verify that the BSL can use a BPA interface to query what block types exist in a bundle.
    def test_BSL_43a(self):
        self._single_test(
            _TestCase(
                # Create a bundle using the vector in RFC9173 Appendix A1.4.
                # Then the BSL will use the BPA host interface to show that there is a primary, payload, and BIB block present.
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Result asserts there are three blocks present, each with the expected type.
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x0A",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    def test_BSL_43b(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [192, 2, 0, 0, h'676F20647261676F6E666C7921'],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Result asserts there are three blocks present, each with the expected type.
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 3, 0, 0, << [2], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'37F54FD9C08B1B9225E74E821EF4EAD35DC850EA98A2B944105447D12D145416DADB83C5123C44BAB0E57C20196EFF060DDCDC7412E948FD46527101E54C201E']]] >>],
    [192, 2, 0, 0, h'676F20647261676F6E666C7921'],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x0A",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_44
    # Query Block Numbers
    # The purpose of this test case is to verify that the BSL can use a BPA interface to query what block numbers are present in a bundle.

    def test_BSL_44(self):
        self._single_test(
            _TestCase(
                # Create a bundle using the vector in RFC9173 Appendix A1.4. Then the BSL will use the BPA host interface to show that there is block 0, 1, and 2 present.
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Test code asserts there are three blocks present, each with the expected id.
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x46",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_45
    # Request BPA Block Contents
    # The purpose of this test case is to verify that the BSL can use a BPA interface to request, from the BPA, block contents associated with a specific block.
    #
    # BSL_10 Unit Test informally satisfied by this fixture
    def test_BSL_45(self):
        self._single_test(
            _TestCase(
                # Create a bundle using the vector in RFC9173 Appendix A1.4. Then the BSL will use the BPA to retrieve the block header fields and BTSD.
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Confirm the resultant bundle after performing the BIB operation in Appendix A1 results in the bundle in Appendix 1.4.
                # This shows the BSL retrieving information from other blocks.
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x46",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_47
    # Add New BPA Blocks
    # The purpose of this test case is to verify that the BSL can use a BPA interface to have the BPA add new blocks to a bundle.
    def test_BSL_47(self):
        self._single_test(
            _TestCase(
                # Create a bundle using the vector in RFC9173 Appendix A1.1. Then the BSL will use the BPA to create a new block for the BIB.
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Test verifies that output matches RFC9173 Appendix A1.4, showing that after BIB source operation a new bundle block with BIB type is created.
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x04",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_48
    # Remove BPA Blocks
    # The purpose of this test case is to verify that the BSL can use a BPA interface to have the BPA remove existing blocks from a bundle.
    def test_BSL_48(self):
        self._single_test(
            _TestCase(
                # Create a bundle using the vector in RFC9173 Appendix A1.4. Then the BSL will use the BPA to validate and remove the BIB block.
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [11, 2, 0, 0, << [1], 1, 1, [2, [2, 1]], [[1, 7], [3, 0]], [[[1, h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]] >>],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # This tests the reverse of the test above.
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                policy_config="0x96",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )

    # BSL_49
    # Modify Block Specific Data
    # The purpose of this test case is to verify that the BSL can use a BPA interface to modify the block-type-specific data of non-security, non-primary blocks.
    def test_BSL_49(self):
        self._single_test(
            _TestCase(
                # Create a bundle using the test vector in RFC9173 Appendix A.2.1
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [1, 1, 0, 0, h'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]
""",
                # Apply the BCB operation per the parameters in Appendix 2, and confirm the final bundle matches the one in Appendix 2.4.
                # This shows BSL modifying BTSD (encrypting).
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                policy_config="0x105",
                bundle_dest_loc=BundleDestLoc.CLIN,
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
                use_bcb_rng=True,
            )
        )

    def test_BCB_verifier(self):
        self._single_test(
            _TestCase(
                input_data="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                expected_output="""\
[_
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
    [12, 2, 1, 0, << [1], 2, 1, [2, [2, 1]], [[1, h'5477656C7665313231323132'], [2, 1], [3, h'69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE700'], [4, 0]], [[[1, h'EFA4B5AC0108E3816C5606479801BC04']]] >>],
    [1, 1, 0, 0, h'3A09C1E63FE23A7F66A59C7303837241E070B02619FC59C5214A22F08CD70795E73E9A']
]
""",
                policy_config="0x165",
                key_set="data/key_set_1.json",
                input_data_format=DataFormat.CBORDIAG,
                expected_output_format=DataFormat.CBORDIAG,
            )
        )
