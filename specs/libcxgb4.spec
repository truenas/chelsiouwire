Summary: Chelsio Open Fabrics Userspace Library
Name: %{name}
Version: %{version}
Release: %{release}
License: Freeware
Group: System Environment/Libraries
URL: www.chelsio.com
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
%define debug_package %{nil}
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%define lib /usr/lib64
%define bin /usr/bin
%define inc /usr/include/chelsio
%define mandir /usr/share/man/man3
%define mandirs /usr/share/man/man7
%define cxdrv /etc/libibverbs.d

%description
libcxgb4_provides a device-specific userspace library for Chelsio 
driver for use with the libibverbs library.

%package devel
Summary: Development files for the libcxgb4 driver
Group: System Environment/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Static version of libcxgb4 that may be linked directly to an
application, which may be useful for debugging.

%prep

%{__mkdir} -p %{name}-%{version}%{lib}
%{__mkdir} -p %{name}-%{version}%{bin}
%{__mkdir} -p %{name}-%{version}%{inc}
%{__mkdir} -p %{name}-%{version}%{mandir}
%{__mkdir} -p %{name}-%{version}%{mandirs}
%{__mkdir} -p %{name}-%{version}%{cxdrv}

find %{srcdir}/libcxgb4/ -name libcxgb4\*.so -type f -exec cp {} %{name}-%{version}%{lib} \;;
find %{name}-%{version}%{lib} -name *.lai -type f -exec rm {} \;
find %{name}-%{version}%{lib} -name *.spec* -type f -exec rm {} \;
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	echo "%{lib}/$(basename $file)" >> %{rpmfiles}
done
cp %{srcdir}/libcxgb4/build/providers/cxgb4/cxgb4.driver %{name}-%{version}%{cxdrv}/ ;
#find %{srcdir}/libcxgb4/ -name cxgb4.driver -type f -exec cp {} %{name}-%{version}%{cxdrv} \;;
echo "%{cxdrv}/cxgb4.driver" >> %{rpmfiles}
find %{srcdir}/libcxgb4/ -name libcxgb4\*.a -type f -exec cp {} %{name}-%{version}%{lib} \;;

%preun
if [ -f  %{lib}/libcxgb4.so ]; then 
    unlink %{lib}/libcxgb4.so;
fi

%post
ln -f -s %{lib}/$(basename $(find %{lib} -name libcxgb4\*.so -type f)) %{lib}/libcxgb4.so

%install

cd %{_topdir}/BUILD/%{name}-%{version}%{lib}
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	%{__install} -D -v $file %{buildroot}%{lib}/$(basename $file)
done

cd %{_topdir}/BUILD/%{name}-%{version}%{cxdrv}
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{cxdrv} 2>/dev/null); do
	%{__install} -D -v $file %{buildroot}%{cxdrv}/$(basename $file)
done
/sbin/ldconfig

%clean
rm -rf %{RPM_BUILD_ROOT}

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(744,root,root)

%files devel
%defattr(-,root,root,-)
%{_libdir}/libcxgb4*.a

%changelog
* Fri Nov 10 2017 root <rallwin@chelsio.com> - 
- libcxgb4 spec file changes.
* Sun Jun 12 2011 root <root@speedy1.blr.asicdesigners.com> - 
- Initial build.

