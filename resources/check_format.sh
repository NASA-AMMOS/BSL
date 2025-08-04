#!/bin/bash
##
## Copyright (c) 2025 The Johns Hopkins University Applied Physics
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
set -e

if [ -z "$SELFDIR" ];
then
    echo "$SELFDIR not defined"
    exit 1
fi

cd $SELFDIR

echo "Check format from root: $SELFDIR"

./resources/apply_format.sh
./resources/apply_license.sh

changed=$(git status --porcelain=1)
if [ -n "${changed}" ]; then
  echo "Error: Files changed after formatting:"
  git diff
  exit 1
fi

exit 0
