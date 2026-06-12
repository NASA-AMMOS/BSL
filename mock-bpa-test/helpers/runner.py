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

import logging
import os
import re
import signal
import subprocess
import time
import threading
from typing import List, Literal, Optional, Union
import queue
from .timer import Timer

LOGGER = logging.getLogger(__name__)
''' Logger for this module. '''
OWNPATH = os.path.dirname(os.path.abspath(__file__))
''' Parent directory path '''
PROJPATH = os.path.abspath(os.path.join(OWNPATH, '..', '..'))
''' Project top path '''


def compose_args(args: List[str]) -> List[str]:
    ''' Combine executions arguments with any prefix scripts and/or tools
    needed to run from the `testroot` environment.
    '''
    args = list(args)

    wrap = os.environ.get('TEST_EXEC_WRAP', '').casefold()
    prefix = []
    if wrap == '':
        pass
    elif wrap == 'memcheck':
        prefix = [
            'valgrind',
            '--tool=memcheck',
            '--leak-check=full', '--show-leak-kinds=all',
            f'--suppressions={PROJPATH}/resources/memcheck.supp',
            '--gen-suppressions=all',
            '--error-exitcode=2',
        ]
    elif wrap == 'helgrind':
        prefix = [
            'valgrind',
            '--tool=helgrind',
            '--error-exitcode=2',
        ]
    elif wrap == 'gdb':
        prefix = [
            'gdb',
            '-batch',
            '-ex', 'handle SIGINT nostop noprint pass',
            '-ex', 'run',
            '-ex', 'bt',
            '--args'
        ]
    else:
        raise ValueError(f'Unhandled TEST_EXEC_WRAP value: {wrap}')

    args = [os.path.join(PROJPATH, 'build.sh'), 'run'] + prefix + args
    return args


WaitStream = Union[Literal['stdout'], Literal['stderr']]
''' Name for output stream '''


class CmdRunner:
    ''' Manage the lifetime of a child process executed from a command.

    :param args: The command arguments to execute including the command
    itself.
    :param kwargs: Additional keyword arguments given to
    :py:func:`subprocess.Popen`
    '''

    def __init__(self, args: List[str], **kwargs):
        self._args = args
        self._kwargs = kwargs

        self.proc: Optional[subprocess.Popen] = None
        self._stdout_reader: Optional[threading.Thread] = None
        self._stderr_reader: Optional[threading.Thread] = None
        self._stdin_writer: Optional[threading.Thread] = None

        self._stdin_lines = queue.Queue()
        self._stdout_lines = queue.Queue()
        self._stderr_lines = queue.Queue()

    def _fmt_args(self):
        return ' '.join([
            '"{}"'.format(arg.replace('"', '\\"')) for arg in self._args
        ])

    def start(self):
        ''' Start a new child process.
        '''
        if self.proc:
            return

        while not self._stdin_lines.empty():
            self._stdin_lines.get()
        while not self._stdout_lines.empty():
            self._stdout_lines.get()
        while not self._stderr_lines.empty():
            self._stderr_lines.get()

        do_stdin = (self._kwargs.setdefault(
            'stdin', subprocess.PIPE) == subprocess.PIPE)
        do_stdout = (self._kwargs.setdefault(
            'stdout', subprocess.PIPE) == subprocess.PIPE)
        do_stderr = (self._kwargs.setdefault(
            'stderr', subprocess.PIPE) == subprocess.PIPE)

        LOGGER.info('Starting process: %s', self._fmt_args())
        self.proc = subprocess.Popen(
            self._args,
            text=True,
            **self._kwargs
        )
        LOGGER.debug('Started with PID %d', self.proc.pid)

        if do_stdin:
            self._stdin_writer = threading.Thread(
                target=self._write_stdin,
                args=[self.proc.stdin],
                daemon=True
            )
            self._stdin_writer.start()

        if do_stdout:
            self._stdout_reader = threading.Thread(
                target=self._read_stdout,
                args=[self.proc.stdout],
                daemon=True
            )
            self._stdout_reader.start()

        if do_stderr:
            self._stderr_reader = threading.Thread(
                target=self._read_stderr,
                args=[self.proc.stderr],
                daemon=True
            )
            self._stderr_reader.start()

    def _finish(self) -> Optional[int]:
        ''' Clean up the process state after exit.
        '''
        if self.proc is None:
            return None

        ret = self.proc.returncode
        self.proc = None
        LOGGER.info('Stopped with exit code: %s', ret)

        if self._stdout_reader:
            self._stdout_reader.join()
            self._stdout_reader = None
        if self._stderr_reader:
            self._stderr_reader.join()
            self._stderr_reader = None

        if self._stdin_writer:
            self._stdin_lines.put(None)
            self._stdin_writer.join()
            self._stdin_writer = None

        return ret

    def poll(self) -> Union[None, Literal[False], int]:
        ''' Check if the process is finished.

        :return: The exit code, None if it is still running, or False if not already running.
        '''
        if not self.proc:
            return False
        return self.proc.poll()

    def wait(self, timeout=5) -> Union[None, Literal[False], int]:
        ''' Wait for the process to finish.

        :param timeout: The time (in seconds) to wait for the process to exit.
        :return: The exit code, or False if not already running.
        :raise subprocess.TimeoutExpired: If the wait has timed out.
        '''
        if not self.proc:
            return False

        LOGGER.info('Waiting on process: %s', self._fmt_args())
        if self.proc.returncode is None:
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._finish()
                raise

        return self._finish()

    def stop(self, timeout=5) -> Optional[int]:
        ''' Signal for the process to stop.
        If the process has not stopped after the timeout, it is killed.

        :param timeout: The time (in seconds) to wait for the process to exit.
        :return: The exit code, or None if it not already running.
        :raise subprocess.TimeoutExpired: If the wait has timed out.
        '''
        if not self.proc:
            return None

        LOGGER.info('Stopping process: %s', self._fmt_args())
        if self.proc.returncode is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                LOGGER.error(
                    'Timed-out after SIGINT, killing process: %s', self._fmt_args())
                self.proc.kill()
                self.proc.wait(timeout=timeout)

        return self._finish()

    def _read_stdout(self, stream):
        LOGGER.debug('Starting stdout thread')
        for line in iter(stream.readline, ''):
            LOGGER.debug('Got stdout: %s', line.strip())
            self._stdout_lines.put(line)
        LOGGER.debug('Stopping stdout thread')
        stream.close()

    def _read_stderr(self, stream):
        LOGGER.debug('Starting stderr thread')
        for line in iter(stream.readline, ''):
            LOGGER.debug('Got stderr: %s', line.strip())
            self._stderr_lines.put(line)
        LOGGER.debug('Stopping stderr thread')
        stream.close()

    def _write_stdin(self, stream):
        LOGGER.debug('Starting stdin thread')
        while True:
            text = self._stdin_lines.get()
            if text is None:
                break
            LOGGER.debug('Sending stdin: %s', text.strip())
            stream.write(text)
            stream.flush()
        LOGGER.debug('Stopping stdin thread')
        stream.close()

    def wait_for_line(self, stream: WaitStream = 'stdout', timeout: float = 5) -> str:
        ''' Wait for any received stdout line.

        :param timeout: The total time to wait for this line.
        :return The matching line.
        :raise TimeoutError: If the line was not seen in time.
        '''
        source = self._stdout_lines if stream == 'stdout' else self._stderr_lines
        try:
            text = source.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError('no lines received before timeout')
        return text

    def wait_for_text(self, pattern: str, stream: WaitStream = 'stdout', timeout: float = 5) -> str:
        ''' Iterate through the received stdout lines until a specific
        full matching line is seen.

        :param pattern: The pattern which must match the full line.
            Use prefix or suffix ".*" as needed.
        :param timeout: The total time (in seconds) to wait for this line.
        :return The matching line.
        :raise TimeoutError: If the line was not seen in time.
        '''
        expr = re.compile(pattern)
        LOGGER.debug('Waiting for pattern "%s" ...', pattern)
        source = self._stdout_lines if stream == 'stdout' else self._stderr_lines

        deadline = Timer(timeout)
        while deadline:
            remain_time = deadline.remaining()
            if remain_time is None:
                break

            try:
                text = source.get(timeout=remain_time)
            except queue.Empty:
                break

            if expr.match(text) is not None:
                return text

        raise TimeoutError('text not received before timeout')

    def send_stdin(self, text: str):
        ''' Send an exact line of text to the process stdin.

        :param text: The line to send, which should include a newline
            at the endd.
        '''
        self._stdin_lines.put(text)

    def close_stdin(self):
        ''' Flush and close the stdin stream.
        '''
        self._stdin_lines.put(None)
