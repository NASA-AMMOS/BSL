#!/bin/bash
##
## Copyright (c) 2024 The Johns Hopkins University Applied Physics
## Laboratory LLC.
##
## This file is part of the Bundle Protocol Security Library (BSL).
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##     http://www.apache.org/licenses/LICENSE-2.0
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##
## This work was performed for the Jet Propulsion Laboratory, California
## Institute of Technology, sponsored by the United States Government under
## the prime contract 80NM0018D0004 between the Caltech and NASA under
## subcontract 1700763.
##

#
# From a fresh checkout perform pre-build steps on this project.
#
set -e

SELFDIR=$(realpath $(dirname "${BASH_SOURCE[0]}"))
source ${SELFDIR}/setenv.sh

cd ${SELFDIR}
cmake -S . -B ${SELFDIR}/build/default \
  -DCMAKE_PREFIX_PATH=${DESTDIR}${PREFIX} \
  -DCMAKE_INSTALL_PREFIX=${DESTDIR}${PREFIX} \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=YES \
  -DTEST_COVERAGE=YES \
  -DTEST_MEMCHECK=YES \
  -DCMAKE_BUILD_TYPE=Debug \
  -G Ninja \
  "$@"
