%define defuser     telego
%define defgroup    %{defuser}
%define pkg_name    telego

################################################################################
%global             debug_package %{nil}
AutoReq:            no
%define             __autoreq %{nil}
%global             __autoreq %{nil}
%global             __requires_exclude_from ^.*$
%global             __find_requires /bin/true
%global             __requires_exclude                     ^user\(
%global             __requires_exclude %__requires_exclude|^group\(
################################################################################

Summary:            Telego telegram MTPRoto service
Name:               %{pkg_name}
Version:            %{_app_version_number}
Release:            %{_app_version_build}
License:            Apache-2.0
Group:              Productivity/Service

URL:                https://github.com/Scratch-net/telego
Source0:            %{pkg_name}
Source1:            %{pkg_name}.service
Source2:            %{pkg_name}.sysconfig
Source3:            %{pkg_name}.logrotate
Source4:            %{pkg_name}.permissions
Source5:            %{pkg_name}.tmpfilesd
Source7:            %{pkg_name}.target
Source9:            %{pkg_name}.toml

BuildRequires:      systemd-rpm-macros
Requires:           systemd
Requires:           logrotate
Requires(pre):      /usr/sbin/groupadd /usr/sbin/useradd /usr/bin/getent
Requires(post):     permissions

Provides:           %{name} = %{version}-%{release}

BuildRoot:          %{_tmppath}/%{name}-%{version}-%{release}-root
ExclusiveArch:      x86_64


%description
Fast MTProxy implementation in Go.


%prep


%build


%install
%{__rm} -rf %{buildroot}
%{__install} -p -D -m 0755 %{SOURCE0} %{buildroot}%{_sbindir}/%{name}
## systemd
%{__install} -D -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/%{name}.service
%{__install} -D -m 644 %{SOURCE7} %{buildroot}%{_unitdir}/%{name}.target
## config
%{__install} -d -m 0750 %{buildroot}%{_sysconfdir}/%{name}
%{__install} -p -D -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/sysconfig/%{name}
%{__install} -p -D -m 0640 %{SOURCE9} %{buildroot}%{_sysconfdir}/%{name}/%{name}.toml
%{__install} -p -D -m 0644 %{SOURCE9} %{buildroot}%{_sysconfdir}/%{name}/config.example.toml
## logrotate
%{__install} -D -m 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/logrotate.d/%{name}
## logdir
%{__install} -d -m 0750 %{buildroot}%{_localstatedir}/log/%{name}
%{__install} -d -m 0700 %{buildroot}%{_datarootdir}/%{name}
## permissions
%{__mkdir_p} %{buildroot}%{_sysconfdir}/permissions.d
%{__install} -p -D -m 0644 %{SOURCE4} %{buildroot}%{_sysconfdir}/permissions.d/%{name}
## tmpfiles and run dir
%{__install} -d -m 0755 %{buildroot}%{_tmpfilesdir}/
%{__install} -p -D -m 0644 %{SOURCE5} %{buildroot}%{_tmpfilesdir}/%{name}.conf
%{__install} -p -d -m 0755 %{buildroot}%{_rundir}/%{name}


%pre
%{_bindir}/getent group %{defgroup} >/dev/null || %{_sbindir}/groupadd -r %{defgroup} || exit 1
%{_bindir}/getent passwd %{defuser} >/dev/null || %{_sbindir}/useradd -g %{defgroup} -M -r -s /bin/false -c "System user for %{pkg_name} service" -d %{_datarootdir}/%{name} %{defuser} || exit 1
%service_add_pre %{name}.service


%post
%service_add_post %{name}.service
%tmpfiles_create %{name}.conf
%set_permissions %{_sbindir}/%{name} %{_sysconfdir}/sysconfig/%{name} %{_sysconfdir}/%{name} %{_sysconfdir}/%{name}/%{name}.toml %{_datarootdir}/%{name} %{_localstatedir}/log/%{name} %{_rundir}/%{name}


%preun
%service_del_preun %{name}.service


%postun
%service_del_postun %{name}.service
# Keep the system account for configuration backups and retained data.


%clean
%{__rm} -rf %{buildroot}


%files
%defattr(-,root,root,-)
%attr(755,root,root) %{_sbindir}/%{name}
%ghost %attr(0755,%{defuser},%{defgroup}) %dir %{_rundir}/%{name}
%attr(0750,%{defuser},%{defgroup}) %dir %{_localstatedir}/log/%{name}
%attr(0750,root,%{defgroup}) %dir %{_sysconfdir}/%{name}
%config(noreplace) %{_unitdir}/%{name}.service
%config(noreplace) %{_unitdir}/%{name}.target
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%attr(0640,root,%{defgroup}) %config(noreplace) %{_sysconfdir}/%{name}/%{name}.toml
%{_sysconfdir}/%{name}/config.example.toml
%{_sysconfdir}/logrotate.d/%{name}
%{_sysconfdir}/permissions.d/%{name}
%{_tmpfilesdir}/%{name}.conf
%attr(0700,%{defuser},%{defgroup}) %dir %{_datarootdir}/%{name}


%changelog
* Wed Mar  4 2026 Alex Geer <monoflash@gmail.com>
- Creating an RPM distribution configuration.
