%define name netdiscover
%define version 0.3beta7
%define release 20060404cvs

Summary: A network address discovering/monitoring tool
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{version}.tar.bz2
License: GPL
Group: Networking/Other
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildArch: i586
BuildRequires: libpcap0-devel libnet2-devel
Requires: libpcap0 libnet2
URL: http://nixgeneration.com/~jaime/netdiscover/

%description
Netdiscover is an active/passive address reconnaissance tool, mainly developed
for those wireless networks without dhcp server, when you are wardriving. It
can be also used on hub/switched networks.

Built on top of libnet and libpcap, it can passively detect online hosts, or
search for them, by actively sending arp requests, it can also be used to
inspect your network arp traffic, and find network addresses using auto scan
mode, which will scan for common local networks.

%prep
%setup

%build
if [ ! -f configure ]
then
   ./autogen.sh
fi
%configure2_5x
%make

%install
%makeinstall
rm -rf $RPM_BUILD_ROOT/usr/doc

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc ChangeLog README AUTHORS INSTALL NEWS TODO
%dir %{_sbindir}/netdiscover
%dir %{_mandir}
%{_mandir}/*


%changelog
* Thu Apr 26 2006 Francis Giraldeau <francis.giraldeau@revolutionlinux.com> - 0.3beta7-20060404cvs
- Correction of installation directories

* Mon Mar 27 2006 Francis Giraldeau <francis.giraldeau@revolutionlinux.com> - 0.3beta6-20060223cvs
- Initial writing
