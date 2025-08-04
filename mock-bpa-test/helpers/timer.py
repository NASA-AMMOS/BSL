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

import logging
import datetime
import time

LOGGER = logging.getLogger(__name__)
''' Logger for this module. '''


class Timer:
    ''' Manager a wall-clock overall timeout timer.
    '''

    def __init__(self, timeout):
        now = datetime.datetime.now(datetime.timezone.utc)
        self._timeout = now + datetime.timedelta(seconds=timeout)

    def sleep(self, delay):
        time.sleep(delay)

    def finish(self):
        self._timeout = None

    def __bool__(self):
        if self._timeout is None:
            return False
        now = datetime.datetime.now(datetime.timezone.utc)
        return now < self._timeout

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._timeout is None:
            return
        now = datetime.datetime.now(datetime.timezone.utc)
        if now > self._timeout:
            raise TimeoutError('Timer did not finish before timeout')
