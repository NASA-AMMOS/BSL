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
from helpers.runner import CmdRunner, Timeout

OWNPATH = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger(__name__)


class TestAgent(unittest.TestCase):
    ''' Verify whole-agent behavior with the bsl-mock-bpa '''

    def setUp(self):
        path = os.path.abspath(os.path.join(OWNPATH, '..'))
        os.chdir(path)
        LOGGER.info('Working in %s', path)

        args = [
            'bash', 'run.sh', 'bsl-mock-bpa',
            '-e', 'ipn:1.2',
            '-u', 'localhost:4556', '-r', 'localhost:14556',
            '-o', 'localhost:24556', '-a', 'localhost:34556',
        ]
        self._agent = CmdRunner(args, stderr=subprocess.STDOUT)

        # Bind underlayer messaging
        self._ul_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._ul_sock.bind(('localhost', 14556))
        self._ul_sock.connect(('localhost', 4556))

        # Bind overlayer messaging
        self._ol_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._ol_sock.bind(('localhost', 34556))

    def tearDown(self):
        self._ol_sock.close()
        self._ol_sock = None

        self._ul_sock.close()
        self._ul_sock = None

        self._agent.stop()
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
