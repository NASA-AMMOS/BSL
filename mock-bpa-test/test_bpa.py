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

OWNPATH = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger(__name__)


class TestAgent(unittest.TestCase):
    ''' Verify whole-agent behavior with the bsl-mock-bpa '''

    def setUp(self):
        path = os.path.abspath(os.path.join(OWNPATH, '..'))
        os.chdir(path)
        LOGGER.info('Working in %s', path)

        args = compose_args([
            'bsl-mock-bpa',
            '-e', 'ipn:1.2',
            '-u', '::1:4556', '-r', '::1:14556',
            '-o', '::1:24556', '-a', '::1:34556',
        ])
        self._agent = CmdRunner(args, stderr=subprocess.STDOUT)

        # Bind underlayer messaging
        self._ul_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._ul_sock.bind(('::1', 14556))
        self._ul_sock.connect(('::1', 4556))

        # Bind overlayer messaging
        self._ol_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._ol_sock.bind(('::1', 34556))

    def tearDown(self):
        self._ol_sock.close()
        self._ol_sock = None

        self._ul_sock.close()
        self._ul_sock = None

        self._agent.stop() # FIXME assert equal to zero?
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
            self.fail('Timeout waiting for data')
        data = sock.recv(65535)
        return data

    def test_deliver_unchanged(self):
        self._start()
        tx_data = self._encode([
            [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
#            [11, 2, 0, 0, binascii.unhexlify(b'810101018202820201828201078203008181820158403BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1')],
            [1, 1, 0, 0, binascii.unhexlify(b'526561647920746F2067656E657261746520612033322D62797465207061796C6F6164')],
        ])
        self._ul_sock.send(tx_data)
        LOGGER.debug('waiting')
        rx_data = self._wait_for(self._ul_sock)
        self.assertEqual(binascii.hexlify(tx_data), binascii.hexlify(rx_data))
