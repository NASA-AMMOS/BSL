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
import datetime
import time
from typing import Optional

LOGGER = logging.getLogger(__name__)
''' Logger for this module. '''


class Timer:
    ''' Manager a wall-clock overall timeout timer.

    :param timeout: The timeout in seconds.
    '''

    def __init__(self, timeout: float):
        self._start = datetime.datetime.now(datetime.timezone.utc)
        self._timeout = self._start + datetime.timedelta(seconds=timeout)

    def elapsed(self) -> float:
        ''' Determine the elapsed time so far.

        :return: The time in seconds.
        '''
        now = datetime.datetime.now(datetime.timezone.utc)
        return (now - self._start).total_seconds()

    def remaining(self) -> Optional[float]:
        ''' Determine the remaining time.

        :return: The remaing time in seconds, or None if already finished.
        '''
        if self._timeout is None:
            return None
        now = datetime.datetime.now(datetime.timezone.utc)
        return (self._timeout - now).total_seconds()

    def sleep(self, delay) -> None:
        ''' Sleep for some portion of the remaining time. '''
        time.sleep(delay)

    def finish(self) -> None:
        ''' Mark the timed activity as being finished.
        '''
        self._timeout = None

    def __bool__(self) -> bool:
        ''' Determine if the timeout has elapsed.
        '''
        if self._timeout is None:
            return False
        now = datetime.datetime.now(datetime.timezone.utc)
        if now > self._timeout:
            raise TimeoutError('Timer did not finish before timeout')
        return now < self._timeout
