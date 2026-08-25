
Name: xrdhttp-pelican
Version: 0.0.13
Release: 1%{?dist}
Summary: A Pelican-specific plugin for the XrdHttp server

Group: System Environment/Daemons
License: BSD
URL: https://github.com/pelicanplatform/xrdhttp-pelican
# Generated from:
# git archive --format tar.gz v%{version} --prefix=xrdhttp-pelican-%{version}/ > ~/rpmbuild/SOURCES/xrdhttp-pelican-%{version}.tar.gz
Source0: %{name}-%{version}.tar.gz

# Build against XRootD 6 by passing `--with xrootd6` to rpmbuild.  Without it
# we build against XRootD 5 (the original default).
%bcond_with xrootd6

%if %{with xrootd6}
%define xrootd_current_major 6
%define xrootd_current_minor 1
%else
%define xrootd_current_major 5
%define xrootd_current_minor 9
%endif
# We have to shell out for EL8 (rpm 4.14) compatibility. rpm 4.16+ (EL9+) accepts %%{expr:...}
%global xrootd_next_minor %(echo $(( %{xrootd_current_minor} + 1)) )

# Since we rely on the private headers, we don't want the plugin to cross
# unknown feature release versions.
BuildRequires: xrootd-devel >= 1:%{xrootd_current_major}.%{xrootd_current_minor}.0
BuildRequires: xrootd-devel <  1:%{xrootd_current_major}.%{xrootd_next_minor}.0
BuildRequires: xrootd-private-devel
BuildRequires: gcc-c++
BuildRequires: cmake

Requires: xrootd-client >= 1:%{xrootd_current_major}.%{xrootd_current_minor}
Requires: xrootd-client <  1:%{xrootd_current_major}.%{xrootd_next_minor}.0

%description
%{summary}

%prep
%setup -q

%build

%cmake3 -DCMAKE_BUILD_TYPE=RelWithDebInfo
pushd %__cmake_builddir
make VERBOSE=1 %{?_smp_mflags}
popd

%install
rm -rf $RPM_BUILD_ROOT
pushd %__cmake_builddir
make install DESTDIR=$RPM_BUILD_ROOT
popd

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/libXrdHttpPelican-*.so

%changelog
* Tue Aug 25 2026 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.13-1
- Add "--with xrootd6" build conditional
- Fix symbol resolution on x86_64 platforms

* Tue Aug 25 2026 Brian Bockelman <bbockelman@morgridge.org> - 0.0.12-1
- Rewrite signal handler to use fewer signal unsafe functions.
  On Linux, the remaining unsafe function should only deadlock if it runs
  concurrently with a dlopen() call.
- Add a watchdog alarm to auto-kill the process if it does happen to
  deadlock during the backtrace printing.

* Tue Mar 03 2026 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.11-1
- Small compatibility fixes
- Handle federation token file in drop-privileges mode

* Fri Jan 23 2026 Brian Bockelman <bbockelman@morgridge.org> - 0.0.10-1
- Fix bug preventing prestaging token from being passed to the filesystem
  layer
- Workaround fact pre-read isn't implemented in XrdPss
- Add regression tests corresponding to the above two issues

* Wed Jan 21 2026 Brian Bockelman <bbockelman@morgridge.org> - 0.0.9-1
- Fix permission issues for prestage when used with token auth
- Add support for re-exec'ing the xrootd binary, allowing it to reload
  the configuration in-place
- Add a signal handler that prints out stack traces on crash

* Mon Dec 08 2025 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.8-1
- Require XRootD 5.9

* Mon Jul 7 2025 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.7-1
- Move authfile and SciTokens config file into the directories owned by xrootd user

* Thu Apr 24 2025 Mátyás Selmeci <mselmeci@wisc.edu> - 0.0.6-1
- Fix EL8 builds

* Tue Apr 22 2025 Matyas Selmeci <mselmeci@wisc.edu> - 0.0.5-1
- Require XRootD 5.8

* Sat Mar 1 2025 Brian Bockelman <bbockelman@morgridge.org> - 0.0.4-1
- Add ability to prestage and evict objects from cache.

* Mon Dec 23 2024 Brian Bockelman <bbockelman@morgridge.org> - 0.0.3-1
- First build of the xrdhttp-pelican plugin
