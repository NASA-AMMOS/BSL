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
# From a fresh checkout perform a full build
#
set -e
set -o pipefail

source setenv.sh

BUILDDIR=${SELFDIR}/build/default

if [ "$1" = "docs" ]
then
    cmake --build ${BUILDDIR} --target docs-api-html
elif [ "$1" = "install" ]
then
    shift
    cmake --install ${BUILDDIR} "$@"
elif [ "$1" = "check" ]
then
    cmake --build ${BUILDDIR} --target test
elif [ "$1" = "coverage" ]
then
    cmake --build ${BUILDDIR} -j1 --target \
        coverage-html coverage-xml
elif [ "$1" = "rpm-container" ]
then
    DOCKER=${DOCKER:-docker}
    DOCKEROPTS=""
    if [[ ${#HOSTNAME} -lt 64 ]]
    then
        echo "Building on ${HOSTNAME}"
        DOCKEROPTS="${DOCKEROPTS} -h ${HOSTNAME}"
    fi
    ${DOCKER} build -f pkg/rpmbuild.Containerfile -t localhost/bsl .
    CID=$(${DOCKER} container create ${DOCKEROPTS} localhost/bsl)

    rm -rf ${SELFDIR}/build ${SELFDIR}/testroot
    mkdir -p ${SELFDIR}/build
    ${DOCKER} cp ${SELFDIR}/. ${CID}:/usr/local/src/bsl

    echo "Executing in container..."
    ${DOCKER} container start -a ${CID}

    mkdir -p build/default/pkg/rpmbuild
    ${DOCKER} cp ${CID}:/usr/local/src/bsl/build/default/pkg/rpmbuild/. ${SELFDIR}/build/default/pkg/rpmbuild

    ${DOCKER} container rm ${CID}
elif [ "$1" = "rpm-build" ]
then
    git config --global --add safe.directory ${PWD}
    ./prep.sh -DBUILD_LIB=NO -DBUILD_TESTING=NO -DBUILD_PACKAGE=YES
    cmake --build build/default --target package_srpm
    cmake --build build/default --target package_rpm

    # Package scanning
    cd build/default/pkg/rpmbuild
    for PKG in RPMS/x86_64/*.rpm
    do
        echo
        rpm -qilp ${PKG}
    done
    rpmlint --file=${SELFDIR}/pkg/rpmlintrc . | tee rpmlint.txt

    # Trial install
    dnf install -y RPMS/x86_64/*.rpm
    dnf repoquery -l 'bsl*'
else
    cmake --build ${BUILDDIR} "$@"
fi
