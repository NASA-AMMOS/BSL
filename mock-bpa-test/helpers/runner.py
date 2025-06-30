
import logging
import re
import signal
import subprocess
import time
import threading
from typing import List
import queue

LOGGER = logging.getLogger(__name__)
''' Logger for this module. '''


class Timeout(RuntimeError):
    ''' Represent a timeout for the CmdRunner class '''


class CmdRunner:
    ''' Manage the lifetime of a child process executed from a command.

    :param args: The command arguments to execute including the command
    itself.
    '''

    def __init__(self, args: List[str], **kwargs):
        self.proc = None
        self._reader = None
        self._args = args
        self._kwargs = kwargs

        self._stdin_lines = queue.Queue()
        self._stdout_lines = queue.Queue()

    def _fmt_args(self):
        return ' '.join([
            '"{}"'.format(arg.replace('"', '\\"')) for arg in self._args
        ])

    def start(self):
        if self.proc:
            return

        while not self._stdout_lines.empty():
            self._stdout_lines.get()

        LOGGER.debug('Starting process: %s', self._fmt_args())
        self.proc = subprocess.Popen(
            self._args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            **self._kwargs
        )
        self._reader = threading.Thread(
            target=self._read_stdout,
            args=[self.proc.stdout]
        )
        self._reader.start()
        self._writer = threading.Thread(
            target=self._write_stdin,
            args=[self.proc.stdin]
        )
        self._writer.start()

    def stop(self, timeout=5):
        if not self.proc:
            return None

        if self.proc.returncode is None:
            LOGGER.debug('Stopping process: %s', self._fmt_args())
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=timeout)

        ret = self.proc.returncode
        self.proc = None
        LOGGER.debug('Stopped with exit code: %s', ret)

        self._reader.join()
        self._reader = None
        self._stdin_lines.put(None)
        self._writer.join()
        self._writer = None

        return ret

    def _read_stdout(self, stream):
        LOGGER.debug('Starting stdout thread')
        for line in iter(stream.readline, ''):
            LOGGER.debug('Got line: %s', line.strip())
            self._stdout_lines.put(line)
        LOGGER.debug('Stopping stdout thread')

    def _write_stdin(self, stream):
        LOGGER.debug('Starting stdin thread')
        while True:
            text = self._stdin_lines.get()
            if text is None:
                break
            LOGGER.debug('Sending text: %s', text)
            stream.write(text)
            stream.flush()
        LOGGER.debug('Stopping stdin thread')

    def wait_for_line(self, timeout=5):
        try:
            text = self._stdout_lines.get(timeout=timeout)
        except queue.Empty:
            raise Timeout()
        return text

    def wait_for_text(self, pattern, timeout=5):
        expr = re.compile(pattern)
        LOGGER.debug('Waiting for pattern "%s" ...', pattern)

        deadline_time = time.time_ns() / 1e9 + timeout
        while True:
            remain_time = deadline_time - time.time_ns() / 1e9
            if remain_time <= 0:
                break
            LOGGER.debug('Waiting for new line up to %s s', remain_time)
            try:
                text = self._stdout_lines.get(timeout=remain_time)
            except queue.Empty:
                raise Timeout()

            if expr.match(text) is not None:
                return text

    def send_stdin(self, text):
        self._stdin_lines.put(text)
