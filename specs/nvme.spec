%{!?kversion:%define kversion %(uname -r)}
%{!?arch:%define arch %(uname -m)}

Summary: Chelsio NVMe Utils for Linux
Name:    %{name}
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Tools
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root

ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc aarch64
ExclusiveOS: linux
Provides: %{name}-%{version}
#requires: python > 2.7.4

%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt
%define bin /sbin
%define pysite %(python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")

%description
The Chelsio NVMe Utils for Linux kernel (%{kversion}).

%pre

for bins in nvme nvmetcli ; do
	if [[ -f %{bin}/${bins} ]] ; then
		mv %{bin}/${bins} %{bin}/${bins}.chold
		rm -rf %{bin}/${bins}
	fi
done
echo "pysite %{pysite}"

%post
easy_install %{pysite}/nvmetcli-0.1*.egg

%postun

for bins in nvme nvmetcli ; do
        if [[ -f %{bin}/${bins}.chold ]] ; then
                mv %{bin}/${bins}.chold %{bin}/${bins}
        fi
done

%prep

%{__mkdir} -p %{name}-%{version}%{bin}
%{__mkdir} -p %{name}-%{version}/%{pysite}

%{__cp} -a %{toolsdir}/nvme_utils/nvmetcli/dist/nvmetcli-0.1*.egg %{name}-%{version}/%{pysite}
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}/%{pysite}/*); do
echo "%{pysite}/$(basename $file)" > %{rpmfiles}
done

%{__cp} -a %{toolsdir}/nvme_utils/nvmetcli/nvmetcli %{name}-%{version}/sbin/
echo "%{bin}/nvmetcli" >> %{rpmfiles}

%{__cp} -a %{toolsdir}/nvme_utils/nvme-cli/nvme %{name}-%{version}/sbin/
echo "%{bin}/nvme" >> %{rpmfiles}


%build

%install

%{__mkdir} -p %{buildroot}/%{pysite}/
cd %{_topdir}/BUILD/%{name}-%{version}%{bin}
%{__install} -D -v -m 755 nvmetcli %{buildroot}%{bin}/nvmetcli
%{__install} -D -v -m 755 nvme     %{buildroot}%{bin}/nvme
cd %{_topdir}/BUILD/%{name}-%{version}/%{pysite}
for file in $(/bin/ls *); do
%{__install} -D -v -m 755 $file %{buildroot}/%{pysite}/
done


%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt

%clean
%{__rm} -rf %{buildroot}

%changelog
