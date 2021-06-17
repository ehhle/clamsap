%ifarch x86_64
  %define platnum   64
  %define platdir   lib64
  %define platstr   64 bit
  %define platform  linuxx86_64
%else
  %define platnum   32
  %define platdir   lib
  %define platstr   32 bit
  %define platform  linuxintel
%endif

%define packname    clamsap-%{version}
%define requiresp   clamav >= 0.96
%define inslibdir   /usr/%{platdir}

Summary:            Virus Scan Adapter (VSA) for ClamAV
Name:               clamsap
Version:            0.103.2
Release:            1
License:            MIT
Group:              Productivity/Security
Source:             %{name}-%{version}.tar.gz
URL:                http://sourceforge.net/projects/clamsap/
BuildRoot:          %{_tmppath}/%{name}-%{version}-build
Provides:           %{packname}
Requires:           %{requiresp}
BuildRequires:      %{requiresp}
%if 0%{?suse_version} >= 1030
BuildRequires:      automake
BuildRequires:      libtool
BuildRequires:      check-devel
BuildRequires:      libbz2-devel
BuildRequires:      libopenssl-devel
%endif
%if 0%{?suse_version} >= 1500
BuildRequires:      clamav-devel
%endif
# additional build dependencies for Fedora/RedHat/SLES10
%if 0%{?fedora_version} || 0%{?rhel_version} || 0%{?centos_version} || 0%{?suse_version} == 1010
BuildRequires:      gcc-c++
%endif


%description
This package provides two %{platstr} shared libraries which link SAP (NW-VSI) and ClamAV
The library clamsap links directly to clamav engine library, the library clamdsap uses the clamd
scan daemon to scan for viruses. Both libraries enable a SAP system to perform antivirus scans.

Authors:
--------
    Markus Strehle

%prep

%setup 

%build
autoreconf --force --install
%configure
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm -rf $RPM_BUILD_ROOT/%_libdir/*.la
rm -rf $RPM_BUILD_ROOT/%_libdir/*.a

%clean  
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%_libdir/lib* 


%changelog
* Thu Jun 30 2016  Markus Strehle
- Fix for block extensions
* Thu Feb 04 2016 Markus Strehle
- Check for archive extract
* Wed Nov 11 2015  Markus Strehle
- Enhance MIME check
- Fix SAP archive decompression
* Wed Oct 21 2015  Markus Strehle
- Fix internal MIME check
* Fri Sep 18 2015  Markus Strehle
- Improve error messages
* Fri May 29 2015  Markus Strehle
- Fix problem, if libmagic can not be found in VsaStartup
- Security fix for compression, see CVE-2015-2282 and CVE-2015-2278
- Enhance buffer scan in libclamdsap
* Fri Mar 27 2015  Markus Strehle
- NW-VSI 2.00 support
* Fri Apr 27 2012  Markus Strehle
- Support remote scan from libclamdsap to clamd
* Fri Mar 25 2011  Markus Strehle
- Prevent multiple byte code initialisation
* Thu Nov 02 2010  Markus Strehle 
- Initial release (source 0.9.6.stable) 
