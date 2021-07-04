%{!?release:%define release 0}
%{!?kversion:%define kversion %(uname -r)}
%define kerver %(echo -n %{kversion} | sed -e 's/-/_/g')

## Summary offload string define.
Summary: Chelsio Terminator 6 %{offload}driver for Linux
Name:    %{name}
Version: %{version}
Release: %{kerver}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>
Provides: %{name}-%{version}
requires: chelsio-series4-firmware > 1.1.0.10, cxgb4 > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc aarch64
ExclusiveOS: linux

%define drvbase /lib/modules/%{kversion}/updates
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%description
The Chelsio Terminator 6 Ethernet Adapter driver for Linux kernel (%{kversion}).

%prep
%{__mkdir} -p %{name}-%{version}/chcr/
%{__cp} -a %{srcdir}/chcr/chcr.ko %{name}-%{version}/chcr/
echo "%{drvbase}/drivers/net/chcr/chcr.ko" > %{rpmfiles}

%build
## Nothing to do here.

%pre

%post
depmod
exit 0

%postun
depmod
exit 0

%install
cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v chcr/chcr.ko %{buildroot}/%{drvbase}/drivers/net/chcr/chcr.ko

%if %{debug_enable}
 %if %{debug_enable_sles}
   %debug_package
 %endif
%endif

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(744,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog
