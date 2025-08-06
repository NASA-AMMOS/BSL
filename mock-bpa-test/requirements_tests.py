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
from _test_util import _TestCase, _TestSet, DataFormat
from _test_util import NO_OUTPUT, FAILURE_CODE, DELETION


# Test Cases specified by the Requirements Document
class _RequirementsCases(_TestSet):

    def __init__(self):
        super().__init__()

        # BSL_2
        # Deterministic Processing Order
        # The purpose of this test case is to verify that BSL shall impose a deterministic processing order for all security blocks.
        self.cases["BSL_02"] = (_TestCase(
            # A bundle with BIB and BCB both targeting the **payload** block, policy to accept both the blocks
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')],
                [11, 3, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [12, 2, 1, 0, bytes.fromhex('8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')]
            ],
            # A bundle with just the **payload** block
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            policy_config='0x186,0x187',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_3
        # Security Block Inclusion
        # The purpose of this test case is to verify that the BSL shall construct security blocks for inclusion in a bundle.
        self.cases["BSL_03"] = (_TestCase(
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
            policy_config='0x04',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_7
        # Removing Security Operations
        # The purpose of this test case is to verify that the BSL can remove security operations from a bundle.
        self.cases["BSL_07"] = (_TestCase(
            # A bundle with a BIB targeting the **payload** block
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # A bundle with just the **payload** block
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            policy_config='0x86',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_12
        # Encode BTSD
        # The purpose of this test case is to verify that the BSL can encode the BTSD produced for a security block in compliance with RFC 9172 encodings.
        self.cases["BSL_12"] = (_TestCase(
            # A bundle with just the primary block
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
            policy_config='0x04',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_13
        # Decode BTSD
        # The purpose of this test case is to verify that the BSL can decode the BTSD of an RFC 9172 encoded security block.
        self.cases["BSL_13"] = (_TestCase(
            # A bundle with a BIB targeting the primary block
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            # Identical bundle output
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # policy_config = BIB_VERIFIER,
            policy_config='0x46',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

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
        # Bundle Primary EIDs:
        #           src     dest
        #       1.  [5.1,   6.1]
        #       2.  [2.1,   5.1]
        #       3.  [3.1,   5.1]
        #       4.  [4.1,   5.1]
        #
        # Can use ONE policy config and "filters"
        # (e.g. source role, BIB policyrule filter should be role src for src_eid=2.1, role ver for 3.1, etc.)
        self.cases["BSL_14a"] = (_TestCase(
            input_data=[
                [7, 0, 0, [2, [6, 1]], [2, [5, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810001018202820201828201078203008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            #
            expected_output=[
                [7, 0, 0, [2, [6, 1]], [2, [5, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810001018202820201828201078203008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            #
            policy_config='0x82',
            is_implemented=True,
            is_working=False,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))
        self.cases["BSL_14b"] = (_TestCase(
            input_data=[
                [7, 0, 0, [2, [5, 1]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810001018202820201828201078203008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            #
            expected_output=[
                [7, 0, 0, [2, [5, 1]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810001018202820201828201078203008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [11, 3, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            #
            policy_config='0x04',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))
        # 14c) need logs to show verification
        self.cases["BSL_14c"] = (_TestCase(
            input_data=[
                [7, 0, 0, [2, [5, 1]], [2, [3, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810001018202820201828201078203008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            #
            expected_output=[
                [7, 0, 0, [2, [5, 1]], [2, [3, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810001018202820201828201078203008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            #
            # policy_config = BIB_VERIFIER,
            policy_config='0x42',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))
        self.cases["BSL_14d"] = (_TestCase(
            input_data=[
                [7, 0, 0, [2, [5, 1]], [2, [4, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810001018202820201828201078203008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            #
            expected_output=[
                [7, 0, 0, [2, [5, 1]], [2, [4, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            #
            policy_config='0x82',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_17
        # BPA Deleting Block
        # The purpose of this test case is to verify that the BSL can request that a BPA delete a security target block when required by policy.
        #
        # Verify that the BSL can request that a BPA delete a security target block when required by policy.
        self.cases["BSL_17"] = (_TestCase(
            # Bundle with a BIB targeting extension block with private use type
            # TODO what is meant by private use type?
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [7, 2, 0, 0, bytes.fromhex('19012C')],  # 2 byte, 012c
                                            # NOTE this differs from RFC9173 A3, uses SHA512 instead of SHA256
                                            # NOTE modified first 2 bytes of signature for failure
                [11, 3, 0, 0, bytes.fromhex('81020101820282020182820107820300818182015840ffff78889abb36f06a2272b88f7fceab74fe69b35b4c5f7b737634ff478d9fd800f0797e2ce6ac0f0d413b34c2196e1e777a180cb63ffc33d2761e386177fa78')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Bundle with removed target block
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 3, 0, 0, bytes.fromhex('81020101820282020182820107820300818182015840ffff78889abb36f06a2272b88f7fceab74fe69b35b4c5f7b737634ff478d9fd800f0797e2ce6ac0f0d413b34c2196e1e777a180cb63ffc33d2761e386177fa78')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            policy_config='0x5E',
            is_implemented=True,
            is_working=False,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_19
        # BPA Deleting Bundle
        # The purpose of this test case is verify that the BSL can request that the BPA delete a bundle when required by policy.
        #
        # 19) need logs to show deletion
        self.cases["BSL_19"] = (_TestCase(
            # Bundle with a BIB targeting primary block
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810001018202820201828201078203008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92dda8ec93df80b41620df5bc6c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # No output because it was deleted, logs to indicate deletion.
            expected_output=(NO_OUTPUT, DELETION),
            policy_config='0x62',
            is_implemented=True,
            is_working=True,
            expect_success=False,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.NONE
        ))

        # BSL_23
        # RFC Compliant Cryptographs
        # The purpose of this test case is to verify that the BSL can alter the contents of non-security blocks to incorporate cryptographic outputs in accordance with RFC 9173.
        #
        # The BIB and BCB test vectors from RFC 9173 demonstrate altering security blocks.
        # The test takes the bundle provided by the unit test (content from RFC 9173) and confirms that after
        # the security operation has been applied, the bundle's blocks match the output described in the test vector.
        #
        # repeat of BSL_2
        self.cases["BSL_23"] = (_TestCase(
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')],
                [11, 3, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [12, 2, 1, 0, bytes.fromhex('8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')]
            ],
            # A bundle with just the **payload** block
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            policy_config='0x186,0x187',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_24
        # Security Block Result Fields
        # The purpose of this test case is to verify that the BSL can place cryptographic material in security block security result fields in accordance with RFC 9172 and RFC 9173.
        self.cases["BSL_24"] = (_TestCase(
            # CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            # Test that following the given BIB operation from Appendix A, the encoded bundle equals the final bundle
            # in the test vector Appendix A.1.4. This shows the cryptographic results were encoded correctly.
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            #
            policy_config='0x04',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_26
        # Retrieving Key Parameters
        # The purpose of this test case is verify that the BSL can retrieve key-related parameters required by key-based security contexts.
        self.cases["BSL_26"] = (_TestCase(
            # CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            # Satisfied by validation for SSF-4-0, as performing the security operations must assemble key material.
            # TODO ???
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            #
            policy_config='0x04',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_27
        # Supporting Security Contents
        # The purpose of this test case is to verify that the BSL can support the security contexts identified in RFC 9173.
        #
        # 2 tests:
        #       CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3 (for BIB).
        #       Second input is CBOR provided in Appendix A2 for BCB https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.2
        # Test that for both BIB-protected and BCB-protected Bundle, the expected results match the final result.
        # This shows that they implement the security context of RFC9173 in Appendix A1 and A2.
        self.cases["BSL_27a"] = (_TestCase(
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            policy_config='0x04',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))
        self.cases["BSL_27b"] = (_TestCase(
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746f2067656e657261746520612033322d62797465207061796c6f6164')]
            ],
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [12, 2, 1, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')]
            ],
            policy_config='0x05',
            is_implemented=True,
            is_working=False,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_28
        # Supporting BCB AES GCM
        # The purpose of this test case is to verify that the BSL can support the use of the BCB-AES-GCM default security context [RFC 9173] for BCB-confidentiality security operations.
        # This is the first half of the validation for SSF-4-0
        # repeat of bsl_27b
        self.cases["BSL_28"] = (_TestCase(
            # Input is CBOR provided in Appendix A2 for BCB https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.2
             input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746f2067656e657261746520612033322d62797465207061796c6f6164')]
            ],
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [12, 2, 1, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')]
            ],
            policy_config='0x05',
            is_implemented=True,
            is_working=False,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_29
        # Supporting BIB HMAC SHA
        # The purpose of this test case is to verify that the BSL can support the use of the BIB-HMAC-SHA default security context [RFC 9173] for bib-integrity security operations.
        #
        # repeat bsl_27a
        self.cases["BSL_29"] = (_TestCase(
            # CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3 (for BIB)
             input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            policy_config='0x04',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_33
        # Reason Code 8
        # The purpose of this test case is to verify that the BSL has the ability to inform the BPA that a block is unintelligible using Reason Code 8 as defined in RFC 9171.
        self.cases["BSL_33"] = (_TestCase(
            # Using the Bundle from RFC 9173 Appendix A1.4, change the bytes of the BIB header to be be all zeros (thus not a valid CBOR array).
            # Header: 850b020000 -> 0000000000
            input_data=bytes.fromhex('9f88070000820282010282028202018202820201820018281a000f42400000000000585681010101820282020182820' \
                                        '1078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb' \
                                        '1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920746f2067656e657' \
                                        '261746520612033322d62797465207061796c6f6164ff'),
            # Confirm that the operations fails and returns a Reason Code 8.
            expected_output=(FAILURE_CODE, 8),
            # Execute as a BIB acceptor.
            policy_config='0x86',
            is_implemented=True,
            is_working=False,
            expect_success=False,
            input_data_format=DataFormat.HEX,
            expected_output_format=DataFormat.ERR
        ))

        # BSL_37
        # Interface Failure
        # The purpose of this test case is verify that the BSL can report on the failure of any interface to perform a requested operation.
        #
        # 37) need logs to show error
        self.cases["BSL_37"] = (_TestCase(
            # Using the Bundle from RFC 9173 Appendix A1.4, change the the block ID of the payload to number 99
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                # assuming "block id" here means block num; if block type was 99, it would be invalid bundle (no payload)
                [1, 99, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')]
            ],
            # Ensure that the host interface returns an error code (since the block does not exist). Confirm that a log indicating this error is created.
            expected_output=(FAILURE_CODE, 0),  # doesn't specify an error code
            policy_config='0x46',
            is_implemented=True,
            is_working=False,
            expect_success=False,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.ERR
        ))

        # BSL_38
        # Processing Error
        # The purpose of this test case is to verify that the BSL can cease processing related security operations when there is a processing error associated with those operations.
        #
        # 38) need logs to show new further sec option processed
        self.cases["BSL_38"] = (_TestCase(
            # Using the bundle created from RFC 9173 Appendix A.2.4. Change the first 10 bytes of the encrypted payload (BTSD of block 1) to be all zeroes.
            # This will cause decryption to fail.
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [12, 2, 1, 0, bytes.fromhex('8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')],
                [1, 1, 0, 0, bytes.fromhex('000000000000000000009c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')]
            ],
            # The security operation will return an error code indicating failure. Additionally, using the telemetry counters and logs,
            # confirm that no further security operation processing was taken (specifically, no BIB operations should be seen).
            expected_output=(FAILURE_CODE, 0),  # doesn't specify an error code
            #
            policy_config='0x87',
            is_implemented=True,
            is_working=False,
            expect_success=False,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.ERR
        ))

        # BSL_43
        # Query Existing Block Types
        # The purpose of this test case is to verify that the BSL can use a BPA interface to query what block types exist in a bundle.
        #
        # TODO should this be  a unit test?
        self.cases["BSL_43"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.4.
            # Then the BSL will use the BPA host interface to show that there is a primary, payload, and BIB block present.
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Result asserts there are three blocks present, each with the expected type.
            # TODO ?
            expected_output=[],
            policy_config='0x87',
            is_implemented=False,
            is_working=False,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_44
        # Query Block Numbers
        # The purpose of this test case is to verify that the BSL can use a BPA interface to query what block numbers are present in a bundle.
        #
        # TODO should this be a unit test?
        self.cases["BSL_44"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.4. Then the BSL will use the BPA host interface to show that there is block 0, 1, and 2 present.
            input_data=[],
            # Test code asserts there are three blocks present, each with the expected id.
            # TODO ?
            expected_output=[],
            policy_config='0x86',
            is_implemented=False,
            is_working=False,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_45
        # Request BPA Block Contents
        # The purpose of this test case is to verify that the BSL can use a BPA interface to request, from the BPA, block contents associated with a specific block.
        #
        # TODO is my interpretation of this language correct?
        self.cases["BSL_45"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.4. Then the BSL will use the BPA to retrieve the block header fields and BTSD.
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Confirm the resultant bundle after performing the BIB operation in Appendix A1 results in the bundle in Appendix 1.4.
            # This shows the BSL retrieving information from other blocks.
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            policy_config='0x46',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_47
        # Add New BPA Blocks
        # The purpose of this test case is to verify that the BSL can use a BPA interface to have the BPA add new blocks to a bundle.
        self.cases["BSL_47"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.1. Then the BSL will use the BPA to create a new block for the BIB.
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Test verifies that output matches RFC9173 Appendix A1.4, showing that after BIB source operation a new bundle block with BIB type is created.
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            policy_config='0x04',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_48
        # Remove BPA Blocks
        # The purpose of this test case is to verify that the BSL can use a BPA interface to have the BPA remove existing blocks from a bundle.
        self.cases["BSL_48"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.4. Then the BSL will use the BPA to validate and remove the BIB block.
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [11, 2, 0, 0, bytes.fromhex('810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # This tests the reverse of the test above.
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            #
            policy_config='0x96',
            is_implemented=True,
            is_working=True,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))

        # BSL_49
        # Modify Block Specific Data
        # The purpose of this test case is to verify that the BSL can use a BPA interface to modify the block-type-specific data of non-security, non-primary blocks.
        self.cases["BSL_49"] = (_TestCase(
            # Create a bundle using the test vector in RFC9173 Appendix A.2.1
            input_data=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746f2067656e657261746520612033322d62797465207061796c6f6164')]
            ],
            # Apply the BCB operation per the parameters in Appendix 2, and confirm the final bundle matches the one in Appendix 2.4.
            # This shows BSL modifying BTSD (encrypting).
            expected_output=[
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [12, 2, 1, 0, bytes.fromhex('8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')],
                [1, 1, 0, 0, bytes.fromhex('3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')]
            ],
            #
            policy_config='0x105',
            is_implemented=True,
            is_working=False,
            expect_success=True,
            input_data_format=DataFormat.BUNDLEARRAY,
            expected_output_format=DataFormat.BUNDLEARRAY
        ))
