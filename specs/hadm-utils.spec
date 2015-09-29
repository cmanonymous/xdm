Name:           hadm
Version:        2.0.0
Release:        1%{?dist}
Summary:        hadm

Group:          System Environment/Kernel
License:	Commercial
URL:            http://skybility.com/product/ha.php
Source:		${name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  libxml2

%description
hadm utilities

%prep
%setup -q

%build
rm -fr kmod
sed -i 's|kmod||' Makefile.am
./autogen.sh
#./configure 
./build.sh
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
make install DEST=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
/opt/hadm/bin/*
/opt/hadm/lib/*
/opt/hadm/log/
/opt/hadm/etc/
