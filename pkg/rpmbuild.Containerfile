FROM quay.io/centos/centos:stream9

RUN dnf config-manager --set-enabled crb
RUN --mount=type=cache,target=/var/cache/yum \
    dnf install -y epel-release
# Dependencies for general RPM building
RUN --mount=type=cache,target=/var/cache/yum \
    dnf install -y git rsync tito rpm-build rpmlint

COPY bsl.spec /usr/local/src/bsl/
WORKDIR /usr/local/src/bsl
RUN --mount=type=cache,target=/var/cache/yum \
    dnf builddep -y bsl.spec

# Container will mount to /usr/local/src/bsl
CMD ["sh", "-c", "./build.sh rpm-build && ./build.sh rpm-check"]
