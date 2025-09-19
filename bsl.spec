%bcond_with apidoc

Name: bsl
Version: 1.0.0
Release: 2%{?dist}
Summary: The Bundle Protocol Security Library (BSL)
URL: https://github.com/NASA-AMMOS/BSL
# License "Apache-2.0" is not accepted by rpmlint
License: ASL 2.0
Source0: %{name}-%{version}.tar.gz

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
Requires: %{name}%{?_isa} = %{version}
%description devel
Development files needed to build and link to the BSL.

%package test
Summary: Unit test and Mock BPA executables for the BSL
%description test
This package contains executables needed to test the associated
BSL library build.

%package test-devel
Summary: Development files for the BSL test fixtures
Requires: %{name}-test%{?_isa} = %{version}
%description test-devel
Development files needed to build and link to the BSL mock BPA.

%if %{with apidoc}
%package apidoc
Summary: API documentation for the BSL
Requires: %{name}%{?_isa} = %{version}
%description apidoc
API documentation in the form of HTML package generated
from the API with Doxygen.
%endif


%prep
%setup -q

./build.sh deps

%cmake -DCMAKE_PREFIX_PATH=${PWD}/testroot/usr \
       -DPROJECT_VERSION=%{version} \
       -DBUILD_UNITTEST=YES -DTEST_MEMCHECK=NO -DTEST_COVERAGE=NO \
       -DBUILD_DOCS_MAN=YES %{?with_apidoc:-DBUILD_DOCS_API=YES}

%build
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

%cmake_install


%files
%license LICENSE
%doc README.md
%{_libdir}/libqcbor.so.*
%{_libdir}/libbsl_front.so.*
%{_libdir}/libbsl_dynamic.so.*
%{_libdir}/libbsl_crypto.so.*
%{_libdir}/libbsl_sample_pp.so.*
%{_libdir}/libbsl_default_sc.so.*

%files devel
%license LICENSE
%doc README.md
%{_includedir}/bsl
%{_includedir}/qcbor
%{_includedir}/m-lib
%{_libdir}/libqcbor.so
%{_libdir}/libbsl_front.so
%{_libdir}/libbsl_dynamic.so
%{_libdir}/libbsl_crypto.so
%{_libdir}/libbsl_sample_pp.so
%{_libdir}/libbsl_default_sc.so

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
%{_includedir}/unity
%{_libdir}/cmake/unity
%{_libdir}/libunity.a
%{_libdir}/libbsl_mock_bpa.so
%{_libdir}/libbsl_test_utils.so

%if %{with apidoc}
%files apidoc
%license LICENSE
%{_docdir}/bsl
%endif


%changelog
* Thu Sep 18 2025 Brian Sipos <brian.sipos@jhuapl.edu> 1.0.0-2
- New package built with tito

* Wed Sep 17 2025 Brian Sipos - 1.0.0-1
- Initial release version.

* Mon Oct 07 2024 Brian Sipos - 0.0.0-0
- Initial development before version tagging.
