FROM ubuntu:22.04 as buildenv-rtems-leon
LABEL org.opencontainers.image.description "RTEMS target environment with GCC compiler"

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y tar xz-utils curl

ADD --link https://www.gaisler.com/anonftp/rcc/rcc-1.3/1.3.2/sparc-rtems-5-gcc-10.5.0-1.3.2-linux.txz /tmp/
RUN mkdir -p /opt && \
    tar -C /opt -xf /tmp/sparc-rtems-5-gcc-10.5.0-1.3.2-linux.txz && \
    rm /tmp/sparc-rtems-5-gcc-10.5.0-1.3.2-linux.txz
ENV PATH="/opt/rcc-1.3.2-gcc/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y \
    cmake ninja-build rsync patch

COPY deps/QCBOR /usr/local/src/QCBOR
COPY deps/mlib /usr/local/src/mlib
COPY deps/unity /usr/local/src/unity
COPY setenv.sh deps.sh deps/*.patch /usr/local/src/
RUN export DEPSDIR=/usr/local/src DESTDIR="" PREFIX=/usr/local && \
    /usr/local/src/deps.sh


FROM ubuntu:22.04 as buildenv-ubuntu-x86
LABEL org.opencontainers.image.description "Ubuntu target environment with GCC compiler"

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y \
    build-essential gcc \
    cmake ninja-build


FROM buildenv-rtems-leon
# The actual library

COPY bsl /usr/local/src/bsl
RUN cd /usr/local/src/bsl && \
    cmake -S . -B build -G Ninja \
	-DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_TOOLCHAIN_FILE=cmake/TC-RTEMS.cmake \
        -DRTEMS_TOOLS_PREFIX=/opt/rcc-1.3.2-gcc && \
    cmake --build build && \
    cmake --install build
