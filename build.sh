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

#
# From a fresh checkout perform a full build
#
set -e
set -o pipefail

source setenv.sh
export SELFDIR=$(realpath $(dirname "${BASH_SOURCE[0]}"))
BUILDDIR=${SELFDIR}/build/default

function usage {
    echo "Usage: $0 [command] [args...]"
    echo "Commands:"
    echo "  check-format   - Apply and check format for all source code"
    echo "  apply-format   - Apply format to all source code"
    echo "  apply-license  - Apply/update license preamble to files"
    echo "  check          - Run unit tests"
    echo "  clean          - Clean build artifacts"
    echo "  deps           - Build dependend libraries"
    echo "  docs           - Build HTML and/or PDF doxygen"
    echo "  install        - Install"
    echo "  lint           - Run clang-tidy code linter"
    echo "  prep [args...] - Generate makefiles with config options"
    echo "  rpm-prep       - Prepare for RPM package building"
    echo "  rpm-build      - Build RPM package after rpm-prep"
    echo "  rpm-check      - Check RPM packages after rpm-build"
    echo "  rpm-container  - Build and check RPM packages inside container"
    echo "  run [args...]  - Run a command with the environment vars"
}

function cmd_check_format {
    ./resources/check_format.sh
}

function cmd_apply_format {
    ./resources/apply_format.sh
}

function cmd_apply_license {
    ./resources/apply_license.sh
}

function cmd_check {
    cmake --build ${BUILDDIR} --target test
}

function cmd_clean {
    rm -rf build testroot deps/build
}

function cmd_coverage {
    cmake --build ${BUILDDIR} -j1 --target \
        coverage-html coverage-xml
}
function cmd_coverage_summary {
    for DIRNAME in backend crypto policy_provider security_context mock_bpa
    do
	COV_XPATH="format-number(/coverage/packages/package[@name='src.${DIRNAME}']/@line-rate * 100, '#.0')"
        COV_PERC=$(xmlstarlet sel -t -v "${COV_XPATH}" -n build/default/coverage-xml.xml 2>/dev/null)
        echo "Source ${DIRNAME} coverage: ${COV_PERC}%"
    done
}

function cmd_deps {
    ./resources/deps.sh
}

function cmd_docs {
    cmake --build ${BUILDDIR} --target docs-api-html
}

function cmd_install {
    shift
    cmake --install ${BUILDDIR} "$@"
}

function cmd_lint {
    cmake --build build/default/ --target clang-tidy
}

function cmd_prep {
    shift
    ./resources/prep.sh "$@"
}

function cmd_rpm_prep {
    if ! git describe 2>/dev/null >/dev/null
    then
        git config --global --add safe.directory ${PWD}
    fi
    ./resources/prep.sh -DBUILD_LIB=OFF -DBUILD_TESTING=OFF -DBUILD_DOCS_API=OFF -DBUILD_DOCS_MAN=OFF -DBUILD_PACKAGE=ON
}

function cmd_rpm_build {
    cmake --build build/default --target package_srpm
    cmake --build build/default --target package_rpm
}

function cmd_rpm_check {
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
}

function cmd_rpm_container {
    DOCKER=${DOCKER:-docker}
    DOCKEROPTS=""
    if [[ ${#HOSTNAME} -lt 64 ]]
    then
        echo "Building on ${HOSTNAME}"
        DOCKEROPTS="${DOCKEROPTS} -h ${HOSTNAME}"
    fi
    ${DOCKER} image build -f pkg/rpmbuild.Containerfile -t localhost/bsl .
    CID=$(${DOCKER} container create ${DOCKEROPTS} localhost/bsl)

    rm -rf ${SELFDIR}/build ${SELFDIR}/testroot
    mkdir -p ${SELFDIR}/build
    ${DOCKER} container cp ${SELFDIR}/. ${CID}:/usr/local/src/bsl

    echo "Executing in container..."
    ${DOCKER} container start -a ${CID}

    mkdir -p build/default/pkg/rpmbuild
    ${DOCKER} container cp ${CID}:/usr/local/src/bsl/build/default/pkg/rpmbuild/. ${SELFDIR}/build/default/pkg/rpmbuild

    echo "Removing container..."
    ${DOCKER} container rm ${CID}

}

function cmd_run {
    # testroot installed files
    DESTDIR=${DESTDIR:-${SELFDIR}/testroot}
    PREFIX=${PREFIX:-/usr}

    if [ -n "${DESTDIR}" -o -n "${PREFIX}" ]
    then
        export LD_LIBRARY_PATH=${DESTDIR}${PREFIX}/lib:${DESTDIR}${PREFIX}/lib64
        export PATH=${PATH}:${DESTDIR}${PREFIX}/bin
    fi

    shift
    exec $@
}

function cmd_default {
    cmake --build ${BUILDDIR} "$@"
}

case "$1" in
    echotest)
        shift
        echo "Test-after-shift: $@"
        ;;
    check-format)
        cmd_check_format
        ;;
    apply-format)
        cmd_apply_format
        ;;
    apply-license)
        cmd_apply_license
        ;;
    check)
        cmd_check
        ;;
    clean)
        cmd_clean
        ;;
    coverage)
        cmd_coverage
        ;;
    coverage-summary)
        cmd_coverage_summary
        ;;
    deps)
        cmd_deps
        ;;
    docs)
        cmd_docs
        ;;
    help|-h|--help)
        usage
        ;;
    install)
        cmd_install "$@"
        ;;
    lint)
        cmd_lint;
        ;;
    prep)
        cmd_prep "$@"
        ;;
    rpm-prep)
        cmd_rpm_prep
        ;;
    rpm-build)
        cmd_rpm_build
        ;;
    rpm-check)
        cmd_rpm_check
        ;;
    rpm-container)
        cmd_rpm_container
        ;;
    run)
        cmd_run "$@"
        ;;
    *)
        cmd_default "$@"
        ;;
esac

