FROM quay.io/centos/centos:stream9

RUN dnf config-manager --set-enabled crb
RUN --mount=type=cache,target=/var/cache/yum dnf install -y epel-release
# Dependencies for library, test executables, bsl-mock-bpa, and apidoc HTML
RUN --mount=type=cache,target=/var/cache/yum dnf install -y \
    rsync cmake git ninja-build gcc ruby \
    openssl-devel \
    doxygen graphviz plantuml texlive-bibtex \
    asciidoctor \
    rpm-build rpmlint

RUN mkdir -p /usr/local/src/bsl
WORKDIR /usr/local/src/bsl
CMD ["./build.sh", "rpm-build"]
