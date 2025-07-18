from _test_util import _TestCase, _TestSet
from _test_util import * 

# Test Cases specified by the Requirements Document
class _RequirementsCases(_TestSet):
    def __init__(self): 
        super().__init__()

        # BSL_2
        self.cases["BSL_2"] = (_TestCase(
            # A bundle with BIB and BCB both targeting the **payload** block, policy to accept both the blocks
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')], 
                [12, 3, 1, 0, bytes.fromhex('8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')]
            ],
            # A bundle with just the **payload** block
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # policy to accept both the blocks
            policy_config = BIB_AND_BCB_ACCEPTOR,
            is_implemented = True,
            expect_success = True,
            input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))


        # BSL_3
        self.cases["BSL_3"] = (_TestCase(
            # A bundle with just the **payload** block
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Bundle with additional BIB
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Policy to add a BIB
            policy_config = BIB_SOURCE,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_7
        self.cases["BSL_7"] = (_TestCase(
            # A bundle with a BIB targeting the **payload** block
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # A bundle with just the **payload** block
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Policy to accept that BIB
            policy_config = BIB_ACCEPTOR,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_12
        self.cases["BSL_12"] = (_TestCase(
            # A bundle with just the primary block
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Bundle with additional BIB
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Policy to add a BIB
            policy_config = BIB_SOURCE,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_13
        self.cases["BSL_13"] = (_TestCase(
            # A bundle with a BIB targeting the primary block
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')], 
            ],
            # Identical bundle output
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # policy to verify that BIB
            policy_config = BIB_VERIFIER,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_14
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
            input_data = [
                [7, 0, 0, [2, [6, 1]], [2, [5, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, '8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e'],
                [1, 1, 0, 0, '526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
            ],
            # 
            expected_output = [
                [7, 0, 0, [2, [6, 1]], [2, [5, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, '8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e'],
                [1, 1, 0, 0, '526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
            ],
            # 
            policy_config = POLICY_UNDEFINED,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))
        self.cases["BSL_14b"] = (_TestCase(
            input_data = [
                [7, 0, 0, [2, [5, 1]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, '8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e'],
                [1, 1, 0, 0, '526561647920746F2067656E657261746520612033322D62797465207061796C6F6164'] 
            ],
            # 
            expected_output = [
                [7, 0, 0, [2, [5, 1]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, '8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e'],
                [11, 3, 0, 0, '810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1'],
                [1, 1, 0, 0, '526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
            ],
            # 
            policy_config = BIB_SOURCE,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))
        # 14c) need logs to show verification
        self.cases["BSL_14c"] = (_TestCase(
            input_data = [
                [7, 0, 0, [2, [5, 1]], [2, [3, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, '8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e'],
                [1, 1, 0, 0, '526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
            ],
            # 
            expected_output = [
                [7, 0, 0, [2, [5, 1]], [2, [3, 1]], [2, [2, 1]], [0, 40], 1000000],  
                [11, 2, 0, 0, '8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e'],
                [1, 1, 0, 0, '526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
            ],
            # 
            policy_config = BIB_VERIFIER,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))
        self.cases["BSL_14d"] = (_TestCase(
            input_data = [
                [7, 0, 0, [2, [5, 1]], [2, [4, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # 
            expected_output = [
                [7, 0, 0, [2, [5, 1]], [2, [4, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # 
            policy_config = BIB_ACCEPTOR,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_17
        # Verify that the BSL can request that a BPA delete a security target block when required by policy. 
        self.cases["BSL_17"] = (_TestCase(
            # Bundle with a BIB targeting extension block with private use type
            # TODO what is meant by private use type?
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [7, 2, 0, 0, bytes.fromhex('19012C')], # 2 byte, 012c
                [11, 3, 0, 0, bytes.fromhex('810201018202820300828201058203008181820158203ED614C0D97F49B3633627779AA18A338D212BF3C92B97759D9739CD50725596')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # No output because it was deleted, logs to indicate deletion.
            expected_output = (NO_OUTPUT, DELETION),
            # policy to verify the BIB and delete target if failed.
            policy_config = BIB_VERIFIER,
            is_implemented = False,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "NONE"
        ))

        # BSL_19
        # 19) need logs to show deletion
        self.cases["BSL_19"] = (_TestCase(
            # Bundle with a BIB targeting primary block
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, '8100010182028202018282010782034200008181820158405d9bdd1e2f043cf971588111f2fe1b847666cfacb7fb403c2468ef92a8ec93df80b41620df5bc639d0c355e1cce6217e17d3b8c5560edc14aba3d005196b046e'],
                [1, 1, 0, 0, '526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
            ],
            # No output because it was deleted, logs to indicate deletion.
            expected_output = (NO_OUTPUT, DELETION),
            # policy to verify the BIB and delete bundle if failed.
            policy_config = BIB_VERIFIER,
            is_implemented = False,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "NONE"
        ))

        # BSL_23a
        # The BIB and BCB test vectors from RFC 9173 demonstrate altering security blocks.
        # The test takes the bundle provided by the unit test (content from RFC 9173) and confirms that after
        # the security operation has been applied, the bundle's blocks match the output described in the test vector.
        self.cases["BSL_23a"] = (_TestCase(
            input_data = [
                [7, 0, 0, [2, [5, 1]], [2, [4, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 3, 0, 0,  bytes.fromhex('')],
                [12, 2, 0, 0,  bytes.fromhex('')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            expected_output = [

            ],
            policy_config = BIB_AND_BCB_SOURCE,
            is_implemented = False,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))


        # BSL_24
        self.cases["BSL_24"] = (_TestCase(
            # CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')], 
            ],
            # Test that following the given BIB operation from Appendix A, the encoded bundle equals the final bundle 
            # in the test vector Appendix A.1.4. This shows the cryptographic results were encoded correctly.
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            # 
            policy_config = BIB_SOURCE,
            is_implemented = False,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_26
        self.cases["BSL_26"] = (_TestCase(
            # CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')], 
            ],
            # Satisfied by validation for SSF-4-0, as performing the security operations must assemble key material.
            # TODO ???
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            # 
            policy_config = POLICY_UNDEFINED,
            is_implemented = False, 
            expect_success = True,
            input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_27
        # 2 tests: 
        #       CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3 (for BIB). 
        #       Second input is CBOR provided in Appendix A2 for BCB https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.2
        # Test that for both BIB-protected and BCB-protected Bundle, the expected results match the final result. 
        # This shows that they implement the security context of RFC9173 in Appendix A1 and A2.
        self.cases["BSL_27a"] = (_TestCase(
            # 
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')], 
            ],
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
            ],
            policy_config = BIB_SOURCE,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))
        self.cases["BSL_27b"] = (_TestCase(
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746f2067656e657261746520612033322d62797465207061796c6f6164')]
            ],
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [12, 2, 1, 0, bytes.fromhex('8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')],
                [1, 1, 0, 0, bytes.fromhex('3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')]
            ],
            policy_config = BCB_SOURCE,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_28
        # TODO 
        self.cases["BSL_28"] = (_TestCase(
            # Input is CBOR provided in Appendix A2 for BCB https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.2
            input_data = [

            ],
            # This is the first half of the validation for SSF-4-0
            expected_output = [

            ],
            # 
            policy_config = POLICY_UNDEFINED,
            is_implemented = False,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_29
        # TODO
        self.cases["BSL_29"] = (_TestCase(
            # CBOR provided in RFC 9173 Appendix A1 https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3 (for BIB)
            input_data = [

            ],
            # This is the second half of the validation for SSF-4-0
            expected_output = [

            ],
            # 
            policy_config = POLICY_UNDEFINED,
            is_implemented = False,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_33
        self.cases["BSL_33"] = (_TestCase(
            # Using the Bundle from RFC 9173 Appendix A1.4, change the bytes of the BIB header to be be all zeros (thus not a valid CBOR array).
            # Header: 850b020000 -> 0000000000
            input_data =    '9f88070000820282010282028202018202820201820018281a000f4240000000000058568101010182028202018282010782030081818' \
                            '20158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6c' \
                            'cece003e95e8164dcc89a156e185010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff',
            # Confirm that the operations fails and returns a Reason Code 8.
            expected_output = (FAILURE_CODE, 8),
            # Execute as a BIB acceptor.
            policy_config = BIB_VERIFIER,
            is_implemented = False,
			expect_success = False,
			input_data_format = "HEX",
            expected_output_format = "ERR"
        ))

        # BSL_37
        # 37) need logs to show error
        self.cases["BSL_37"] = (_TestCase(
            # Using the Bundle from RFC 9173 Appendix A1.4, change the the block ID of the payload to number 99
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                # assuming "block id" here means block num; if block type was 99, it would be invalid bundle (no payload)
                [1, 99, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')]
            ],
            # Ensure that the host interface returns an error code (since the block does not exist). Confirm that a log indicating this error is created.
            expected_output = (FAILURE_CODE, 0), # doesn't specify an error code
            policy_config = BIB_VERIFIER,
            is_implemented = False,
			expect_success = False,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "ERR"
        ))

        # BSL_38
        # 38) need logs to show new further sec option processed
        self.cases["BSL_38"] = (_TestCase(
            # Using the bundle created from RFC 9173 Appendix A.2.4. Change the first 10 bytes of the encrypted payload (BTSD of block 1) to be all zeroes. 
            # This will cause decryption to fail.
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [12, 2, 1, 0, bytes.fromhex('8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')],            
                [1, 1, 0, 0, bytes.fromhex('000000000000000000009c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')]
            ],
            # The security operation will return an error code indicating failure. Additionally, using the telemetry counters and logs, 
            # confirm that no further security operation processing was taken (specifically, no BIB operations should be seen).
            expected_output = (FAILURE_CODE, 0), # doesn't specify an error code
            # 
            policy_config = BCB_ACCEPTOR,
            is_implemented = False,
			expect_success = False,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "ERR"
        ))

        # BSL_43
        #TODO should this be  a unit test?
        self.cases["BSL_43"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.4. 
            # Then the BSL will use the BPA host interface to show that there is a primary, payload, and BIB block present.
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Result asserts there are three blocks present, each with the expected type.
            # TODO ?
            expected_output = [],
            policy_config = POLICY_UNDEFINED,
            is_implemented = False,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_44
        # TODO should this be  a unit test?
        self.cases["BSL_44"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.4. Then the BSL will use the BPA host interface to show that there is block 0, 1, and 2 present.
            input_data = [],
            # Test code asserts there are three blocks present, each with the expected id.
            # TODO ?
            expected_output = [],
            policy_config = POLICY_UNDEFINED,
            is_implemented = False,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_45
        # TODO is my interpretation of this language correct?
        self.cases["BSL_45"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.4. Then the BSL will use the BPA to retrieve the block header fields and BTSD.
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Confirm the resultant bundle after performing the BIB operation in Appendix A1 results in the bundle in Appendix 1.4.
            # This shows the BSL retrieving information from other blocks.
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            policy_config = BIB_VERIFIER,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_47
        self.cases["BSL_47"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.1. Then the BSL will use the BPA to create a new block for the BIB.
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # Test verifies that output matches RFC9173 Appendix A1.4, showing that after BIB source operation a new bundle block with BIB type is created.
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            policy_config = BIB_SOURCE,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_48
        self.cases["BSL_48"] = (_TestCase(
            # Create a bundle using the vector in RFC9173 Appendix A1.4. Then the BSL will use the BPA to validate and remove the BIB block.
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [11, 2, 0, 0, bytes.fromhex('8101010182028202018282010782034200008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1')],
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # This tests the reverse of the test above.
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000], 
                [1, 1, 0, 0, bytes.fromhex('526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')]
            ],
            # 
            policy_config = BIB_ACCEPTOR,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))

        # BSL_49
        self.cases["BSL_49"] = (_TestCase(
            # Create a bundle using the test vector in RFC9173 Appendix A.2.1
            input_data = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [1, 1, 0, 0, bytes.fromhex('526561647920746f2067656e657261746520612033322d62797465207061796c6f6164')]
            ],
            # Apply the BCB operation per the parameters in Appendix 2, and confirm the final bundle matches the one in Appendix 2.4. 
            # This shows BSL modifying BTSD (encrypting).
            expected_output = [
                [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                [12, 2, 1, 0, bytes.fromhex('8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04')],
                [1, 1, 0, 0, bytes.fromhex('3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a')]
            ],
            # 
            policy_config = BCB_SOURCE,
            is_implemented = True,
			expect_success = True,
			input_data_format = "BUNDLEARRAY",
            expected_output_format = "BUNDLEARRAY"
        ))
