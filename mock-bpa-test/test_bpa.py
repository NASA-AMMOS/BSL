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
''' Simple I/O tests of the mock agent.
'''
import io
import logging
import os
import select
import signal
import socket
import subprocess
import time
from typing import Any, List, Optional
import unittest
import cbor2
from cbor_diag import diag2cbor, cbor2diag

from helpers import CmdRunner, compose_args
from _test_util import _TestCase, DataFormat, BundleDestLoc

OWNPATH = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger(__name__)


class TestAgent(unittest.TestCase):
    ''' Verify whole-agent behavior with the bsl-mock-bpa '''

    def __init__(self, methodName="runTest"):
        super().__init__(methodName)

    def setUp(self):

        path = os.path.abspath(os.path.join(OWNPATH, '..'))
        os.chdir(path)
        LOGGER.info('Working in %s', path)

        self._agent = None
        self._ol_sock = None
        self._ul_sock = None

    def tearDown(self):
        self._stop()

    def _stop(self):
        if self._ol_sock:
            self._ol_sock.close()
            self._ol_sock = None
        if self._ul_sock:
            self._ul_sock.close()
            self._ul_sock = None
        if self._agent:
            # Exit cleanly if not already gone
            ret = self._agent.stop()
            self._agent = None

            self.assertEqual(0, ret)

    def _start(self, testcase: Optional[_TestCase]):
        self.assertIsNone(self._agent)
        self.assertIsNone(self._ul_sock)
        self.assertIsNone(self._ol_sock)

        pol_is_json = False
        use_bcb_rng = False

        sec_src_eid = 'ipn:2.1'

        if testcase is not None:
            policy_config = testcase.policy_config
            LOGGER.info('Using policy config %s', policy_config)

            if testcase.sec_src_eid:
                sec_src_eid = testcase.sec_src_eid

            pol_is_json = policy_config.endswith(".json")

            use_bcb_rng = testcase.use_bcb_rng
            key_set = testcase.key_set
            # freshen derived file
            if key_set.endswith('.cbordiag'):
                key_file = key_set[:-4]
                with (
                    open(os.path.join(OWNPATH, key_set), 'r') as infile,
                    open(os.path.join(OWNPATH, key_file), 'wb') as outfile
                ):
                    outfile.write(diag2cbor(infile.read()))
                key_set = key_file

        else:
            policy_config = "0x00"
            key_set = "data/key_set_1.json"

        arglist = [
            'bsl-mock-bpa',
            '-s', sec_src_eid,
            '-u', 'localhost:4556', '-r', 'localhost:14556',
            '-o', 'localhost:24556', '-a', 'localhost:34556',
            '-j' if pol_is_json else "-p", policy_config,
            '-k', key_set
        ]
        arglist += ['-c'] if use_bcb_rng else []
        args = compose_args(arglist)
        self._agent = CmdRunner(args, cwd=OWNPATH, stderr=subprocess.STDOUT)

        # Bind underlayer messaging
        self._ul_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._ul_sock.bind(('localhost', 14556))
        self._ul_sock.connect(('localhost', 4556))

        # Bind overlayer messaging
        self._ol_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._ol_sock.bind(('localhost', 34556))
        self._ol_sock.connect(('localhost', 24556))

        ''' Spawn the process and wait for the startup READY message. '''
        self._agent.start()
        self._agent.wait_for_text(r'.* <INFO> \[.+\:MockBPA_Agent_Exec] READY$')

    def _encode(self, input: Any, format: DataFormat) -> Optional[bytes]:
        if format == DataFormat.HEX:
            return bytes.fromhex(input)

        elif format == DataFormat.BUNDLEARRAY:
            buf = io.BytesIO()
            buf.write(b'\x9F')
            for blk in input:
                cbor2.dump(blk, buf)
            buf.write(b'\xFF')
            LOGGER.debug('Encoded to data %s', buf.getvalue().hex())
            return buf.getvalue()

        elif format == DataFormat.CBORDIAG:
            return diag2cbor(input)

        elif format == DataFormat.ANYCBOR:
            return None

        else:
            raise ValueError(f"Unhandled data format {format}")

    def _wait_for(self, sock: socket.socket) -> bytes:

        LOGGER.debug('Waiting for socket data...')
        rrd, rwr, rxp = select.select([sock], [], [], 1.0)
        if not rrd:
            raise TimeoutError('Did not receive bundle in time')
        data = sock.recv(65535)
        LOGGER.debug(f'WAIT FOR GOT: {data.hex()}')
        return data

    def _single_test(self, testcase: Optional[_TestCase]):

        # start mock BPA using specified policy config
        self._start(testcase)

        tx_data = self._encode(testcase.input_data, testcase.input_data_format)

        test_sock = self._ol_sock if testcase.bundle_dest_loc == BundleDestLoc.APPIN else self._ul_sock

        if testcase.expected_output_format == DataFormat.ERR:
            test_sock.send(tx_data)
            LOGGER.debug('waiting')

            with self.assertRaises(TimeoutError):
                self._wait_for(test_sock)

            LOGGER.info('\nTransferred data:\n%s\n', tx_data.hex())

            LOGGER.warning('Check log output to validate expected error')

            err_case_str = testcase.expected_output
            LOGGER.debug(f'ERR CASE STR: {err_case_str}')

            LOGGER.debug("Searching test runner logger for error string: %s", err_case_str)
            found = self._agent.wait_for_text(err_case_str)
            LOGGER.debug("\nFOUND OCCURENCE: %s", found)
            self.assertNotEqual("", found)

        else:
            # actual data
            expected_rx = self._encode(testcase.expected_output, testcase.expected_output_format)

            test_sock.send(tx_data)
            LOGGER.info('Sent data:\n%s\n', tx_data.hex())

            rx_data = self._wait_for(test_sock)
            if expected_rx is not None:
                LOGGER.info('Expected data:\n%s\n', expected_rx.hex())
            LOGGER.info('Received data:\n%s\n', rx_data.hex())

            LOGGER.debug('CBOR diagnostic of received data:\n%s\n', cbor2diag(rx_data))

            if expected_rx is not None:
                self.assertEqual(expected_rx.hex(), rx_data.hex())


class TestStartStop(TestAgent):
    ''' Basic verification of the daemon itself '''

    def test_start_stop(self):
        self._start(None)
        ret = self._agent.stop()
        self._agent = None
        self.assertEqual(0, ret)
