%{!?release:%define release 0}
%{!?kversion:%define kversion %(uname -r)}
%{!?arch:%define arch %(uname -m)}
%define kerver %(echo -n %{kversion} | sed -e 's/-/_/g')

## Summary offload string define.
Summary: Chelsio Terminator LIO-target driver for Linux
Name:    %{name}
Version: %{version}
Release: %{kerver}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>
Provides: %{name}-%{version}
requires: cxgb4 > 1.1.0.10, chelsio-series4-firmware > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc aarch64
ExclusiveOS: linux

%define drvbase /lib/modules/%{kversion}/updates/kernel
%define mandir /usr/share/man/man8
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%define debug_package %{nil}

%description
The Chelsio Terminator LIO-target driver and utils for Linux kernel (%{kversion}).

%prep
## chiscsi driver
%{__mkdir} -p %{name}-%{version}/cxgbit/
%{__cp} -a %{srcdir}/cxgbit.ko %{name}-%{version}/cxgbit/
echo "%{drvbase}/drivers/target/iscsi/cxgbit/cxgbit.ko" > %{rpmfiles}

%build
## Nothing to do here.

%pre

%post
## Generate new module dependencies.
depmod
exit 0

%preun

%postun
## Update module dependencies.
depmod
exit 0

%install
cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v cxgbit/cxgbit.ko %{buildroot}%{drvbase}/drivers/target/iscsi/cxgbit/cxgbit.ko

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(744,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog
