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
import contextlib
import json
import logging
import tempfile
from collections.abc import Generator
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Any, Optional

LOGGER = logging.getLogger(__name__)


@unique
class DataFormat(IntEnum):
    BUNDLEARRAY = 0
    """ Python structures used with cbor2 library. """
    HEX = 1
    """ Data is hex-encoded bytes """
    ERR = 2
    """ No expected output, the error log is scanned """
    CBORDIAG = 4
    """ Full CBOR diagnostic notation with cbor-diag library. """
    ANYCBOR = 5
    """ Output is not deterministic, any well-formed CBOR is acceptable """


@unique
class BundleDestLoc(IntEnum):
    APPIN = 0
    CLIN = 1


@dataclass
# Holds a simple test case
class _TestCase:
    input_data: Any
    """ representation of input bundle """
    input_data_format: DataFormat
    """ data format of :py:attr:`input_data` """

    policy_config: str
    """ decimal digit representing uint32 for policy configuration OR path to JSON-encoded ION-like policy rules """

    key_set: str
    """ path to JWK-encoded key set (named .json) or COSE_KeySet (named .cbor) """

    expected_output: Any
    """ either list representation of expected output bundle OR a string to search log output for match """
    expected_output_format: DataFormat
    """     data format of :py:attr:`expected_output` """

    sec_src_eid: Optional[str] = None
    """ Security source for all operations """

    bundle_dest_loc: BundleDestLoc = BundleDestLoc.CLIN
    """ local outgoing interaction point of the output bundle """

    use_bcb_rng: bool = False
    """ If true, test will use custom rng callback for BCB testing """


@contextlib.contextmanager
def sc_config_modifier(
    orig: str, modify: Optional[dict[str, Any]] = None, role: Optional[str] = None
) -> Generator[str, None, None]:
    """A context for modifying baseline configurations

    :param orig: The original file path, relative to this directory.
    :param modify: Updates to the context parameters, either modifying or adding.
    :return: A generator for temporary files which exist for the duration
        of this context.
    """
    with tempfile.NamedTemporaryFile("w+", suffix=".json") as polfile:
        with open(orig, "r") as infile:
            poldata = json.load(infile)

        rule = poldata["policyrule_set"][0]["policyrule"]

        if role:
            rule["filter"]["role"] = role

        if modify:
            params = rule["spec"]["sc_parms"]
            LOGGER.debug("Original params:\n%s", params)
            if isinstance(params, dict):
                params |= modify
            elif isinstance(params, list):
                # replace existing
                for pair in params:
                    key = pair["id"]
                    if key in modify:
                        pair["value"] = str(modify.pop(key))
                # add remaining
                for key, val in modify.items():
                    params.append({"id": key, "value": str(val)})
            else:
                raise TypeError(f"bad type {type(params)}")
            LOGGER.debug("Modified params:\n%s", params)

        json.dump(poldata, polfile)
        polfile.flush()
        yield polfile.name
