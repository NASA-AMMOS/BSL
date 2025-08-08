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
''' Simple I/O tests of the mock agent.
'''
import binascii
import io
import logging
import os
import select
import signal
import socket
import subprocess
import time
from typing import List
import unittest
import cbor2

from helpers import CmdRunner, compose_args
from _test_data import _TestData
from _test_util import _TestCase, _TestSet, DataFormat
from requirements_tests import _RequirementsCases
from ccsds_tests import _CCSDS_Cases

OWNPATH = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger(__name__)


class TestAgent(unittest.TestCase):
    ''' Verify whole-agent behavior with the bsl-mock-bpa '''

    def __init__(self, methodName="runTest"):
        super().__init__(methodName)
        # self.testdata = _TestData()
        self.requirements_tests = _RequirementsCases()
        # self.ccsds_tests = _CCSDS_Cases()
        self.pp_cfg_dict = {}
        for id, tc in self.requirements_tests.cases.items():
            self.pp_cfg_dict[id] = tc.policy_config
        # for id, tc in self.ccsds_tests.cases.items():
        #     self.pp_cfg_dict[id] = tc.policy_config

    def setUp(self):

        path = os.path.abspath(os.path.join(OWNPATH, '..'))
        os.chdir(path)
        LOGGER.info('Working in %s', path)

        try:
            policy_config = str(self.pp_cfg_dict[self._testMethodName[5:]])
            LOGGER.info('Using policy config from DICT %s for %s', policy_config, self._testMethodName[5:])
        except Exception:
            policy_config = self._testMethodName
            # Find the index of the first occurrence of "_p" policy sequence
            index = policy_config.index("_p")
            # Slice the string from index + 1 to the end
            policy_config = policy_config[index + 2:]
            LOGGER.info('Using policy config %s for %s', policy_config, self._testMethodName)

        key_set = "src/mock_bpa/key_set_1.json"

        args = compose_args([
            'bsl-mock-bpa',
            '-e', 'ipn:2.1',
            '-u', 'localhost:4556', '-r', 'localhost:14556',
            '-o', 'localhost:24556', '-a', 'localhost:34556',
            '-p', policy_config,
            '-k', key_set
        ])
        self._agent = CmdRunner(args, stderr=subprocess.STDOUT)

        # Bind underlayer messaging
        self._ul_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._ul_sock.bind(('localhost', 14556))
        self._ul_sock.connect(('localhost', 4556))

        # Bind overlayer messaging
        self._ol_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._ol_sock.bind(('localhost', 34556))
        self._ol_sock.connect(('localhost', 24556))

    def tearDown(self):

        self._ol_sock.close()
        self._ol_sock = None

        self._ul_sock.close()
        self._ul_sock = None

        if self._agent:
            # Exit cleanly if not already gone
            ret = self._agent.stop()

            self.assertEqual(0, ret)
            self._agent = None

    def _start(self):

        ''' Spawn the process and wait for the startup READY message. '''
        self._agent.start()
        self._agent.wait_for_text(r'.* <INFO> \[.+\:bpa_exec] READY$')

    def _encode(self, blocks: List[object]):

        buf = io.BytesIO()
        buf.write(b'\x9F')
        for blk in blocks:
            cbor2.dump(blk, buf)
        buf.write(b'\xFF')
        LOGGER.debug('Encoded to data %s', binascii.hexlify(buf.getvalue()))
        return buf.getvalue()

    def _wait_for(self, sock: socket.socket) -> bytes:

        LOGGER.debug('Waiting for socket data...')
        rrd, rwr, rxp = select.select([sock], [], [], 1.0)
        if not rrd:
            raise TimeoutError('Did not receive bundle in time')
        data = sock.recv(65535)
        return data

    def _single_test(self, testcase: _TestCase):

        # start mock BPA using specified policy config
        self._start()

        tx_data = testcase.input_data if (testcase.input_data_format == DataFormat.HEX) else self._encode(testcase.input_data)

        if (testcase.expected_output_format == DataFormat.BUNDLEARRAY):
            expected_rx = testcase.expected_output if (testcase.expected_output == "HEX") else self._encode(testcase.expected_output)

            self._ul_sock.send(tx_data)
            LOGGER.debug('waiting')

            rx_data = self._wait_for(self._ul_sock)

            LOGGER.info('\nTransferred data:\n%s\n', binascii.hexlify(tx_data))
            LOGGER.info('\nReceived data:\n%s\n', binascii.hexlify(rx_data))

            cbor_str = cbor2.loads(rx_data)
            LOGGER.info('\nCBOR representation of received data:\n%s\n', cbor_str)

            print(f'exp: {binascii.hexlify(expected_rx)}, got: {binascii.hexlify(rx_data)}')

            self.assertEqual(binascii.hexlify(expected_rx), binascii.hexlify(rx_data))

        elif (testcase.expected_output_format == DataFormat.NONE):
            self._ul_sock.send(tx_data)
            LOGGER.debug('waiting')

            with self.assertRaises(TimeoutError):
                self._wait_for(self._ul_sock)

            LOGGER.info('\nTransferred data:\n%s\n', binascii.hexlify(tx_data))

            LOGGER.warning('Check log output to validate reason for no data!!')

            # Currently hard-coded for test case 19 but no other instances of DataFormat.NONE
            case_19_str = r".*Delete bundle due to failed security operation"

            LOGGER.debug("Searching test runner logger for failure string: %s", case_19_str)
            found = self._agent.wait_for_text(case_19_str)
            LOGGER.debug("\nFOUND OCCURENCE: %s", found)
            self.assertTrue(found != "")

        elif (testcase.expected_output_format == DataFormat.ERR):
            self._ul_sock.send(tx_data)
            LOGGER.debug('waiting')

            with self.assertRaises(TimeoutError):
                self._wait_for(self._ul_sock)

            LOGGER.info('\nTransferred data:\n%s\n', binascii.hexlify(tx_data))

            LOGGER.warning('Check log output to validate expected error')

            # TBD - this logic is not used yet
            err_case_str = r"tbd"

            LOGGER.debug("Searching test runner logger for error string: %s", err_case_str)
            found = self._agent.wait_for_text(err_case_str)
            LOGGER.debug("\nFOUND OCCURENCE: %s", found)
            self.assertTrue(found != "")


# Below utilizes setattr to add methods to a child class of the TestAgent, which will in-turn give us unit tests
# tldr auto-generated methods for unit tests :)
# @param new_tests needs to be a class that is child of _TestSet()
def _add_tests(new_tests: _TestSet):

    def decorator(cls):
        for id, tc in new_tests.cases.items():
            if tc.is_implemented and tc.is_working:

                def _test(cls, id=id):
                    cls._single_test(new_tests.cases[id])

                setattr(cls, f'test_{id}', _test)

        return cls

    return decorator


@_add_tests(_RequirementsCases())
# @_add_tests(_TestData())
# @_add_tests(_CCSDS_Cases())
class TestMockBPA(TestAgent):

    def test_start_stop_p00(self):
        self._start()
        time.sleep(0.5)
        self.assertEqual(0, self._agent.stop())
        self._agent = None
