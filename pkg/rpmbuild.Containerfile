FROM quay.io/centos/centos:stream9

RUN --mount=type=cache,target=/var/cache/yum \
    dnf install -y 'dnf-command(config-manager)' epel-release
RUN dnf config-manager --set-enabled crb
# Dependencies for general RPM building
RUN --mount=type=cache,target=/var/cache/yum \
    dnf install -y git rsync rpm-build rpmlint python3-pip python3-wheel python3-setuptools
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install tito

COPY bsl.spec /usr/local/src/bsl/
WORKDIR /usr/local/src/bsl
RUN --mount=type=cache,target=/var/cache/yum \
    dnf builddep -y bsl.spec

# Container will mount to /usr/local/src/bsl
CMD ["sh", "-c", "./build.sh rpm-build && ./build.sh rpm-check"]
