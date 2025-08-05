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

# Apply copyright and license markings to source files.
#
# Requires installation of:
#  pip3 install licenseheaders
# Run as:
#  ./apply_license.sh {specific dir}
#
set -e

if [ -z "$SELFDIR" ];
then
  echo "SELFDIR not defined"
  exit 1
fi

cd $SELFDIR

LICENSEOPTS="${LICENSEOPTS} --tmpl ${SELFDIR}/resources/apply_license.tmpl"
LICENSEOPTS="${LICENSEOPTS} --years $(date +%Y)"
# Excludes only apply to directory (--dir) mode and not file mode
LICENSEOPTS="${LICENSEOPTS} --exclude=${SELFDIR}/docs/api/*.md"


# Specific paths
if [[ $# -gt 0 ]]
then
    echo "Applying markings to selected $@ ..."
    licenseheaders ${LICENSEOPTS} --dir $@
    exit 0
fi


echo "Applying markings to source..."
# Directory trees
for DIRNAME in resources cmake src test mock-bpa-test docs pkg .github
do
    licenseheaders ${LICENSEOPTS} --dir ${SELFDIR}/${DIRNAME}
done
# Specific top-level files
for FILEPATH in $(find "${SELFDIR}" -maxdepth 1 -type f)
do
    licenseheaders ${LICENSEOPTS} --file ${FILEPATH}
done
