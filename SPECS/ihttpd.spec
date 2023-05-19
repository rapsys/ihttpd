%global __brp_check_rpaths %{nil}
%define _disable_ld_no_undefined 1
# (luigiwalser, ngompa): httpd build hates parallelization
%define _smp_ncpus_max 8
%define contentdir %{_datadir}/httpd
%define docroot /var/www
%define vstring Mageia

%{?!maxmodules:%global maxmodules 128}
%{?!serverlimit:%global serverlimit 1024}

Name:		ihttpd
Version:	2.4.57
Release:	%mkrel 1
Summary:	The most widely used Web server on the Internet
License:	ASL 2.0
Group:		System/Servers
URL:		http://httpd.apache.org/
Source0:	http://www.apache.org/dist/httpd/httpd-%version.tar.bz2
Source1:	index.bin.c
Source2:	reboot.sh
Source15:	ihttpd.service
Source16:	debug-sshd.service
Source18:	ihttpd.dracut
Source19:	ihttpd.module-setup
Source20:	ihttpd.conf
# build/scripts patches
Patch1:		httpd-2.4.1-apctl.patch
Patch2:		httpd-2.4.9-apxs.patch
Patch3:		httpd-2.4.1-deplibs.patch
Patch5:		ihttpd-2.4.20-layout.patch
Patch6:		httpd-2.4.3-apctl-systemd.patch
Patch7:		httpd-2.4.10-detect-systemd.patch
# Features/functional changes
Patch20:	httpd-2.4.3-release.patch
#Disable in ihttpd to avoid build fail
#Patch23:	httpd-2.4.4-export.patch
Patch24:	httpd-2.4.1-corelimit.patch
#Patch26:	httpd-2.4.4-r1337344+.patch
Patch27:	httpd-2.4.2-icons.patch
Patch28:	httpd-2.4.4-r1332643+.patch
# http://marc.info/?l=apache-httpd-dev&m=134867223818085&w=2
Patch29:	httpd-2.4.27-systemd.patch
Patch30:	httpd-2.4.4-cachehardmax.patch
#Patch31:	httpd-2.4.18-sslmultiproxy.patch
Patch34:	httpd-2.4.17-socket-activation.patch
#Patch35:	httpd-2.4.33-sslciphdefault.patch
# Bug fixes
# http://issues.apache.org/bugzilla/show_bug.cgi?id=32524
Patch100:   httpd-2.4.25-ab_source_address.patch
Patch101:   httpd-2.2.10-ldap_auth_now_modular_in-apr-util-dbd-ldap_fix.diff

# For /var/www/html
Requires:	webserver-base
# For /etc/mime.types
Requires:	mailcap

Requires(post):	systemd >= %{systemd_required_version}
Requires(post):	rpm-helper >= 0.24.8-1
Requires(post):	openssl makedev
Requires(preun):	rpm-helper >= 0.24.8-1

BuildRequires:  bison
BuildRequires:  flex
BuildRequires:  libcurl-devel
BuildRequires:  libtool >= 1.4.2
BuildRequires:  multiarch-utils >= 1.0.3
BuildRequires:  pkgconfig(apr-1) >= 1.7.0-4
BuildRequires:  pkgconfig(apr-util-1) >= 1.6.1-5
BuildRequires:  pkgconfig(libpcre2-8)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(zlib)

%description
This package contains the main binary of apache, a powerful, full-featured,
efficient and freely-available Web server. Apache is also the most popular Web
server on the Internet.

This version of apache is fully static, and few modules are available built-in.

%prep
%setup -q -n httpd-%{version}

%patch1 -p1 -b .apctl
%patch2 -p1 -b .apxs
%patch3 -p1 -b .deplibs
%patch5 -p1 -b .layout
%patch6 -p1 -b .apctlsystemd
%patch7 -p1 -b .detectsystemd

#Disable in ihttpd to avoid build fail
#%patch23 -p1 -b .export
%patch24 -p1 -b .corelimit
#%patch26 -p1 -b .r1337344+
%patch27 -p1 -b .icons
%patch29 -p1 -b .systemd
%patch30 -p1 -b .cachehardmax
# No longer applies
#%patch31 -p1 -b .sslmultiproxy
%patch34 -p1 -b .socketactivation
#%patch35 -p1 -b .sslciphdefault
#patch44 -p1 -b .luaresume

%patch100 -p1 -b .ab_source_address.droplet
%patch101 -p0 -b .PR45994.droplet

# Patch in vendor/release string
sed "s/@RELEASE@/%{vstring}/" < %{PATCH20} | patch -p1

# forcibly prevent use of bundled apr, apr-util, pcre
rm -rf srclib/{apr,apr-util,pcre}

# fix apxs
perl -pi \
	-e 's|\@exp_installbuilddir\@|%{_libdir}/httpd/build|;' \
	-e 's|get_vars\("prefix"\)|"%{_libdir}/httpd/build"|;' \
	-e 's|get_vars\("sbindir"\) . "/envvars"|"\$installbuilddir/envvars"|;' \
	support/apxs.in

# correct perl paths
find -type f -print0 | xargs -0 perl -pi \
	-e 's|/usr/local/bin/perl|perl|g;' \
	-e 's|/usr/local/bin/perl5|perl|g;' \
	-e 's|/path/to/bin/perl|perl|g;'

# bump max modules
perl -pi \
	-e 's/DYNAMIC_MODULE_LIMIT \d+/DYNAMIC_MODULE_LIMIT %{maxmodules}/;' \
	include/httpd.h

# bump server limit
perl -pi \
	-e 's/DEFAULT_SERVER_LIMIT \d+/DEFAULT_SERVER_LIMIT %{serverlimit}/' \
	server/mpm/prefork/prefork.c \
	server/mpm/worker/worker.c \
	server/mpm/event/event.c

# don't try to touch srclib
perl -pi -e "s|^SUBDIRS = .*|SUBDIRS = os server modules support|g" Makefile.in

# this will only work if configured correctly in the config (FullOs)...
cp server/core.c server/core.c.untagged

# Install index.bin source
install -m 644 %{SOURCE1} index.bin.c 

%build
%serverbuild
# regenerate configure scripts
autoheader && autoconf || exit 1

# Required to be able to run as root
export CFLAGS="$RPM_OPT_FLAGS -DBIG_SECURITY_HOLE"
ldflags_hacky_workaround_for_systemd_lib_not_added="-lsystemd "
export LDFLAGS="${ldflags_hacky_workaround_for_systemd_lib_not_added}-Wl,-z,relro,-z,now"

# Hard-code path to links to avoid unnecessary builddep
export LYNX_PATH=/usr/bin/links

%configure \
	--enable-layout=IHttpd \
	--sysconfdir='/etc' \
	--includedir='/usr/include/ihttpd' \
	--libexecdir='/usr/lib64/ihttpd/modules' \
	--datadir='/usr/share/ihttpd' \
	--with-ssl \
	--with-mpm=prefork \
	--with-cgi \
	--with-program-name='%name' \
	--disable-suexec \
	--without-suexec \
	--disable-distcache \
	--enable-unixd \
	--enable-auth-basic \
	--enable-authn-core \
	--enable-authn-file \
	--enable-authz-core \
	--enable-authz-host \
	--enable-authz-user \
	--enable-rewrite \
	--enable-socache-shmcb \
	--enable-mime \
	--enable-dir \
	--enable-ssl \
	--enable-log-config \
	--enable-cgi \
	--enable-pie \
	--enable-modules=none \
	--enable-mods-static='unixd auth_basic authn_core authn_file authz_core authz_host authz_user rewrite socache_shmcb dir mime log_config cgi ssl'

# parallel build fails on the build host
%__make

export CFLAGS="$RPM_OPT_FLAGS"
gcc index.bin.c -o index.bin

%install

#IHttpd sbin
install -D -p -m 755 ihttpd %{buildroot}%{_sbindir}/ihttpd

#IHttpd dracut config
install -D -p -m 644 %{SOURCE18} %{buildroot}%{_sysconfdir}/dracut.conf.d/99-%{name}.conf

#IHttpd dracut module
install -d -m 755 %{buildroot}%{_prefix}/lib/dracut/modules.d/99ihttpd
install -D -p -m 755 %{SOURCE19} %{buildroot}%{_prefix}/lib/dracut/modules.d/99ihttpd/module-setup.sh

#Ihttpd files
install -d -m 755 %{buildroot}%{_prefix}/lib/%{name}
install -D -p -m 755 index.bin %{buildroot}%{_prefix}/lib/%{name}/
install -D -p -m 755 %{SOURCE2} %{buildroot}%{_prefix}/lib/%{name}/reboot.bin
install -D -p -m 644 %{SOURCE20} %{buildroot}%{_prefix}/lib/%{name}/
install -D -p -m 644 %{SOURCE15} %{buildroot}%{_prefix}/lib/%{name}/
install -D -p -m 644 %{SOURCE16} %{buildroot}%{_prefix}/lib/%{name}/

%post
%_create_ssl_certificate %{name}

%files -n %name
%config(noreplace) %{_prefix}/lib/%{name}/%{name}.conf
%config(noreplace) %{_sysconfdir}/dracut.conf.d/99-%{name}.conf
%{_sbindir}/%{name}
%dir %{_prefix}/lib/dracut/modules.d/99ihttpd
%{_prefix}/lib/dracut/modules.d/99ihttpd/module-setup.sh
%dir %{_prefix}/lib/%{name}
%{_prefix}/lib/%{name}/%{name}.service
%{_prefix}/lib/%{name}/debug-sshd.service
%{_prefix}/lib/%{name}/index.bin
%{_prefix}/lib/%{name}/reboot.bin
