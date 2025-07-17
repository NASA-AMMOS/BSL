# "structure" to hold a simple test case
class _TestCase:
    '''
    @param input_data list representation of bundle | TODO hex option / fully hex?
    @param expected_output either list representation of expected output bundle OR tuple for outcome (FAILURE_CODE, N), (NO_OUTPUT, N), etc.
    @param policy_config decimal digit representing uint32 for policy configuration | TODO switch to a hex string?
    @param impl - boolean, true if test is implemented, false if not (placeholder for empty test fixtures)
    @param success - boolean, true if input bundle is expected to have an output bundle, false if error/no output
    '''
    def __init__(self, input_data, expected_output, policy_config, is_implemented : bool, expect_success: bool, input_data_format : str):
        self.input_data = input_data
        self.expected_output = expected_output
        self.policy_config = policy_config

        # can be removed once all tests are implemeneted
        self.is_implemented = is_implemented

        # true if test expected to succeed (return output bundle with no errors)
        self.expect_success = expect_success

        # "HEX" or "BUNDLEARRAY"
        self.input_data_format = input_data_format


class _TestSet:
    def __init__(self):
        self.cases = {}

# TODO update these to match pp conf
# may need more / different ones as well
POLICY_UNDEFINED = 0
BIB_AND_BCB_ACCEPTOR = 1
BIB_AND_BCB_VERIFIER = 1
BIB_AND_BCB_SOURCE = 1

BIB_ACCEPTOR = 1
BIB_VERIFIER = 1 
BIB_SOURCE = 1

BCB_ACCEPTOR = 1
BCB_VERIFIER = 1 
BCB_SOURCE = 1

NO_OUTPUT = 0
FAILURE_CODE = -1
DELETION = -2