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
#requires: chelsio-series4-firmware > 1.1.0.10, cxgb4 > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc aarch64
ExclusiveOS: linux

%define drvbase /lib/modules/%{kversion}/updates
%define incdir /usr/local/include/spdk
%define libdir /usr/local/lib/
%define bindir /usr/local/bin/
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt
%define spdkincdir %{srcdir}/../chspdk/user/spdk/build/include/spdk
%define spdklibdir %{srcdir}/../chspdk/user/spdk/build/lib/
%define spdkbindir %{srcdir}/../chspdk/user/spdk/build/bin/

%description
The Chelsio Terminator 6 Ethernet Adapter driver for Linux kernel (%{kversion}).

%prep
%{__mkdir} -p %{name}-%{version}/chtcp/
%{__mkdir} -p %{name}-%{version}/chtcp/chspdk/
%{__cp} -a %{srcdir}/chtcp/chtcp.ko %{name}-%{version}/chtcp/
%{__cp} -a %{spdkincdir} %{name}-%{version}/chtcp/chspdk/
%{__cp} -a %{spdklibdir} %{name}-%{version}/chtcp/chspdk/
%{__cp} -a %{spdkbindir}/nvmf_tgt %{name}-%{version}/chtcp/chspdk/

echo "%{drvbase}/drivers/chtcp/chtcp.ko" >> %{rpmfiles}
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}/chtcp/chspdk/spdk); do
echo "%{incdir}/$(basename $file)" >> %{rpmfiles}
done
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}/chtcp/chspdk/lib); do
echo "%{libdir}/$(basename $file)" >> %{rpmfiles}
done
echo "%{bindir}/nvmf_tgt" >> %{rpmfiles}
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
%{__mkdir} -p %{buildroot}/%{libdir}/
%{__mkdir} -p %{buildroot}/%{incdir}/
%{__mkdir} -p %{buildroot}/%{bindir}/
cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v chtcp/chtcp.ko %{buildroot}/%{drvbase}/drivers/chtcp/chtcp.ko
cd %{_topdir}/BUILD/%{name}-%{version}/chtcp/chspdk/spdk
for file in $(/bin/ls *); do
%{__install} -D -v -m 644 $file %{buildroot}/%{incdir}/
done
cd %{_topdir}/BUILD/%{name}-%{version}/chtcp/chspdk/lib
for file in $(/bin/ls *); do
%{__install} -D -v -m 644 $file %{buildroot}/%{libdir}/
done
cd %{_topdir}/BUILD/%{name}-%{version}/chtcp/chspdk/
%{__install} -D -v -m 755 nvmf_tgt %{buildroot}/%{bindir}/nvmf_tgt

%if %{debug_enable}
 %if %{debug_enable_sles}
   %debug_package
 %endif
%endif


%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(755,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog
