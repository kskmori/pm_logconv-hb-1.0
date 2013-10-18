########################################
# Derived definitions
########################################
%define name pm_logconv
%define cluster hb
%define version 1.3
%define release 1
%define prefix /usr
%define instdir pm_logconv
%define ORGARCH %{name}-%{version}
#
#
Summary: Pacemaker and Heartbeat log converter
Name: %{name}-%{cluster}
Version: %{version}
Release: %{release}%{?dist}
Group: Applications
Source: %{name}-%{version}.tar.gz
License: GPL
Vendor: NIPPON TELEGRAPH AND TELEPHONE CORPORATION
BuildRoot: %{_tmppath}/%{name}-%{version}
BuildRequires: make
BuildArch: noarch
Requires: python >= 2.4, python < 3.0
Requires: pacemaker >= 1.0.9, pacemaker < 1.1
Requires: heartbeat >= 3.0.3

########################################
%description
Log message converter for Pacemaker and Heartbeat.
support version
    Pacemaker : stable-1.0 (1.0.9 or more)
    Heartbeat : 3.0.3

########################################
%prep
########################################
rm -rf $RPM_BUILD_ROOT

########################################
%setup -q
########################################

########################################
%build
########################################

########################################
%configure
########################################

########################################
%pre
########################################

########################################
%install
########################################
make DESTDIR=$RPM_BUILD_ROOT install

########################################
%clean
########################################
if
	[ -n "${RPM_BUILD_ROOT}" -a "${RPM_BUILD_ROOT}" != "/" ]
then
	rm -rf $RPM_BUILD_ROOT
fi
rm -rf $RPM_BUILD_DIR/%{ORGARCH}

########################################
%post
########################################
true
########################################
%preun
########################################
true
########################################
%postun
########################################
true

########################################
%files
########################################
%defattr(-,root,root)
%dir /etc
%config /etc/pm_logconv.conf
%dir %{prefix}/share/pacemaker/%{instdir}
%{prefix}/share/pacemaker/%{instdir}/pm_logconv.py
