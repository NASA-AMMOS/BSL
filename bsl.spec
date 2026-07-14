%bcond_with apidoc

Name: bsl
Version: 1.1.1
Release: 1%{?dist}
Summary: The Bundle Protocol Security Library (BSL)
URL: https://github.com/NASA-AMMOS/BSL
# License "Apache-2.0" is not accepted by rpmlint
License: ASL 2.0
Source0: %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires: rsync
BuildRequires: cmake
BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: openssl-devel
BuildRequires: jansson-devel
BuildRequires: asciidoctor
%if %{with apidoc}
BuildRequires: doxygen
BuildRequires: graphviz
BuildRequires: texlive-bibtex
%endif

%description
Runtime files needed to use the BPSec Library (BSL).


%package devel
Summary: Development files for the BSL
Requires: %{name}%{?_isa} = %{version}-%{release}
%description devel
Development files needed to build and link to the BSL.

%package test
Summary: Unit test and Mock BPA executables for the BSL
Requires: %{name}%{?_isa} = %{version}-%{release}
%description test
This package contains executables needed to test the associated
BSL library build.

%package test-devel
Summary: Development files for the BSL test fixtures
Requires: %{name}-test%{?_isa} = %{version}-%{release}
%description test-devel
Development files needed to build and link to the BSL mock BPA.

%if %{with apidoc}
%package doc
Summary: API documentation for the BSL
Requires: %{name}%{?_isa} = %{version}-%{release}
%description doc
API documentation in the form of HTML package generated
from the API with Doxygen.
%endif


%prep
%setup -q


%build
# non-package dependencies into ./testroot
DESTDIR=${PWD}/testroot ./build.sh deps

%cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
       -DCMAKE_PREFIX_PATH=${PWD}/testroot/usr \
       -DPROJECT_VERSION=%{version} \
       -DBUILD_UNITTEST=YES -DTEST_MEMCHECK=NO -DBUILD_COVERAGE=NO \
       -DBUILD_DOCS_MAN=YES -DBUILD_DOCS_API=%{?with_apidoc:YES}%{!?with_apidoc:NO}

%cmake_build 
%cmake_build --target docs-man
%if %{with apidoc}
%cmake_build --target docs-api-html
%endif


%install
# Only during this stage can the {buildroot} be written to

pushd testroot%{_includedir}
for FN in $(find . -type f)
do 
    install -m644 -D ${FN} %{buildroot}%{_includedir}/${FN}
done
popd

pushd testroot%{_libdir}
mkdir -p %{buildroot}%{_libdir}
for FN in $(find . -type f,l -a -name '*.so*')
do 
    cp -a ${FN} %{buildroot}%{_libdir}/${FN}
done
for FN in $(find . -type f -a \( -name '*.a' -o -name '*.cmake' \) )
do
    install -m644 -D ${FN} %{buildroot}%{_libdir}/${FN}
done
popd
install -m644 -D testroot/usr/lib/pkgconfig/m-lib.pc %{buildroot}%{_datadir}/pkgconfig/m-lib.pc

%cmake_install


%check
%cmake_build --target test


%files
%license LICENSE
%doc README.md
%{_libdir}/libqcbor.so.*
%{_libdir}/libbsl_front.so.*
%{_libdir}/libbsl_dynamic.so.*
%{_libdir}/libbsl_crypto.so.*
%{_libdir}/libbsl_sample_pp.so.*
%{_libdir}/libbsl_default_sc.so.*
%{_libdir}/libbsl_cose_sc.so.*

%files devel
%license LICENSE
%doc README.md
%{_includedir}/m-lib/
%{_datadir}/pkgconfig/m-lib.pc

%{_includedir}/qcbor/
%{_libdir}/pkgconfig/qcbor.pc
%{_libdir}/cmake/qcbor/
%{_libdir}/libqcbor.so

%{_includedir}/bsl/
%{_libdir}/pkgconfig/bsl.pc
%{_libdir}/pkgconfig/bsl-default-sc.pc
%{_libdir}/pkgconfig/bsl-cose-sc.pc
%{_libdir}/pkgconfig/bsl-sample-pp.pc
%{_libdir}/libbsl_front.so
%{_libdir}/libbsl_dynamic.so
%{_libdir}/libbsl_crypto.so
%{_libdir}/libbsl_sample_pp.so
%{_libdir}/libbsl_default_sc.so
%{_libdir}/libbsl_cose_sc.so

%files test
%license LICENSE
%doc README.md
%{_libdir}/libbsl_mock_bpa.so.*
%{_libdir}/libbsl_test_utils.so.*
%{_libexecdir}/%{name}/test*
%{_bindir}/bsl-mock-bpa
%{_mandir}/man1/bsl-mock-bpa.*

%files test-devel
%license LICENSE
%doc README.md
%{_includedir}/unity/
%{_libdir}/cmake/unity/
%{_libdir}/libunity.a

%{_libdir}/libbsl_mock_bpa.so
%{_libdir}/libbsl_test_utils.so

%if %{with apidoc}
%files doc
%license LICENSE
%doc %lang(en) %{_docdir}/bsl
%endif


%changelog
* Thu Jun 04 2026 Brian Sipos <brian.sipos@jhuapl.edu> 1.1.1-1
- Build RPM in release mode and fix uses of assert (#196)
- This resolves bug #197 for BCB decrypt.

* Fri May 15 2026 Brian Sipos <brian.sipos@jhuapl.edu> - 1.1.0-1
- Updates for ION v4.2 integration, adding memory and logging callbacks.
- Reorganize JSON policy decoder from bsl_mock_bpa into bsl_sample_pp library.

* Thu Sep 18 2025 Brian Sipos <brian.sipos@jhuapl.edu> 1.0.0-2
- New package built with tito.

* Wed Sep 17 2025 Brian Sipos <brian.sipos@jhuapl.edu> - 1.0.0-1
- Initial release version.

* Mon Oct 07 2024 Brian Sipos - 0.0.0-0
- Initial development before version tagging.
