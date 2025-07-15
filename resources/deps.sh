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
# From a fresh checkout install local-sourced dependencies.
#
set -e

if [ -z "$SELFDIR" ]
then
  echo "SELFDIR not defined"
  exit 1
fi
cd $SELFDIR

# SELFDIR=$(realpath $(dirname "${BASH_SOURCE[0]}"))
source ${SELFDIR}/setenv.sh

DEPSDIR=${DEPSDIR:-${SELFDIR}/deps}
BUILDDIR=${BUILDDIR:-${SELFDIR}/deps/build}
echo "Building in ${BUILDDIR}"
echo "Installing to ${DESTDIR}"

mkdir -p ${BUILDDIR}

# Note: This checks for existence of qcbor, and if exists
# then skips rebuilding it.
if [ ! -e ${DESTDIR}/usr/include/qcbor ]
then
  echo "Building QCBOR..."
  pushd ${DEPSDIR}/QCBOR
  cmake -S . -B ${BUILDDIR}/QCBOR \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_INSTALL_PREFIX=${DESTDIR}${PREFIX}
  cmake --build ${BUILDDIR}/QCBOR
  cmake --install ${BUILDDIR}/QCBOR
  rm -rf ${BUILDDIR}/QCBOR
  ! git status || git restore .
  popd
fi


# Note: This checks for existence of this path, skips building
# if already exists.
if [ ! -e ${DESTDIR}/usr/include/m-lib ]
then
  echo "Building MLIB..."
  rsync --recursive ${DEPSDIR}/mlib/ ${BUILDDIR}/mlib/
  pushd ${BUILDDIR}/mlib
  
  make -j$(nproc)
  make install PREFIX=${PREFIX} DESTDIR=${DESTDIR}
  make -j$(nproc) clean
  popd
fi


# Note: Skips building unity if this path already exists.
if [ ! -e ${DESTDIR}/usr/include/unity ]
then
  echo "Building Unity..."
  pushd ${DEPSDIR}/unity
  cmake -S . -B ${BUILDDIR}/unity \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INSTALL_PREFIX=${DESTDIR}${PREFIX}
  cmake --build ${BUILDDIR}/unity
  cmake --install ${BUILDDIR}/unity
  rm -rf ${BUILDDIR}/unity
  popd
fi

if [ ! -e ${DESTDIR}/usr/include/jansson.h ]
then
  echo "Building jansson..."
  pushd ${DEPSDIR}/jansson
  cmake -S . -B ${BUILDDIR}/jansson \
      -DCMAKE_INSTALL_PREFIX=${DESTDIR}${PREFIX} \
      -DJANSSON_BUILD_SHARED_LIBS=OFF \
      -DJANSSON_BUILD_DOCS=OFF
  cmake --build ${BUILDDIR}/jansson
  cmake --install ${BUILDDIR}/jansson
  rm -rf ${BUILDDIR}/jansson
  popd
fi