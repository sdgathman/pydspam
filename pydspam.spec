%define __python %{__python2}
%define pythonbase python
%define cgibin %{_localstatedir}/www/cgi-bin
%define htmldir %{_localstatedir}/www/html

Summary: A Python wrapper for Dspam Bayesian spam filtering
Name: %{pythonbase}-pydspam
Version: 1.4.0
Release: 1%{dist}
License: GPL
URL: http://www.bmsi.com/python/dspam.html
Group: Development/Libraries
Source: http://bmsi.com/python/pydspam-%{version}.tar.gz
#Patch: pydspam.patch
Buildroot: /var/tmp/pydspam-root
Requires: dspam >= 3.10 %{__python}
# Dspam.py currently hardwires this driver
Requires: dspam-hash
BuildRequires: %{pythonbase}-devel dspam-devel
BuildRequires: policycoreutils policycoreutils-python
Obsoletes: dspam-python

%description
DSPAM (as in De-Spam) is an open-source project to create a new kind of
anti-spam mechanism, and is currently effective as both a server-side agent
for UNIX email servers and a developer's library for mail clients, other
anti-spam tools, and similar projects requiring drop-in spam filtering.

DSPAM has had its core engine moved into a separate library, libdspam.
This library can be used by developers to provide 'drop-in' spam filtering for
their mail client applications, other anti-spam tools, or similar projects. 

A python extension module provides access to the DSPAM core engine from
python.  Additional DSPAM utilities written in python are provided.
Install this if you wish to use DSPAM from python.

%package selinux
Summary: SELinux policy module for pydspam
Group: System Environment/Base
Requires: policycoreutils, selinux-policy, %{name}
BuildRequires: policycoreutils, checkpolicy

%description selinux
SELinux policy module for using pydspam with apache with selinux enforcing

%prep
%setup -q -n pydspam-%{version}
#%patch -p0 -b .bms

%build
env CFLAGS="$RPM_OPT_FLAGS" %{__python} setup.py build
checkmodule -m -M -o pydspam.mod pydspam.te
semodule_package -o pydspam.pp -m pydspam.mod

%install
# provide maintenance scripts
ETCDIR="$RPM_BUILD_ROOT%{_sysconfdir}"
mkdir -p $ETCDIR/cron.hourly
cat >$ETCDIR/cron.hourly/dspam <<'EOF'
#!/bin/sh
cd /var/lib/dspam
exec >>reprocess.log 2>&1
%{_libexecdir}/pydspam/pydspam_process.py *.spam *.fp
EOF
chmod a+x $ETCDIR/cron.hourly/dspam

# provide sample dspam.cfg
mkdir -p $ETCDIR/mail/dspam
cp -p dspam.cfg $ETCDIR/mail/dspam

# install CGI script
CGIDIR="$RPM_BUILD_ROOT%{cgibin}"
HTMLDIR="$RPM_BUILD_ROOT%{htmldir}"
mkdir -p $HTMLDIR/dspam
mkdir -p $CGIDIR
# Use suexec to run CGI
cat >$CGIDIR/pydspam.cgi <<'EOF'
#!/bin/sh
cd %{htmldir}/dspam
exec /usr/sbin/suexec dspam dspam dspamcgi.py
EOF
cp -p dspamcgi.py $HTMLDIR/dspam
chmod 0755 $HTMLDIR/dspam/dspamcgi.py $CGIDIR/pydspam.cgi
cp -p template.html $HTMLDIR/dspam
cp -p base.css $HTMLDIR/dspam
cp -p Maxwells.gif $HTMLDIR/dspam/logo.gif

# install python module
%{__python} setup.py install --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
while read file; do
  case "$file" in
  *.so) strip $RPM_BUILD_ROOT$file;;
  esac
done <INSTALLED_FILES

# install python utilities
mkdir -p $RPM_BUILD_ROOT%{_libexecdir}/pydspam
cp -p dspam_anal.py $RPM_BUILD_ROOT%{_libexecdir}/pydspam/pydspam_anal
cp -p dspam_corpus.py $RPM_BUILD_ROOT%{_libexecdir}/pydspam/pydspam_corpus
cp -p pydspam_process.py $RPM_BUILD_ROOT%{_libexecdir}/pydspam

# install logrotate entry
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
cp -p pydspam.logrotate $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/pydspam

# install selinux modules
mkdir -p %{buildroot}%{_datadir}/selinux/targeted
cp -p pydspam.pp %{buildroot}%{_datadir}/selinux/targeted

%files -f INSTALLED_FILES
%defattr(-,root,root)
%license LICENSE
%doc NEWS dspam.html dspam_dump.py Notes*
/etc/cron.hourly/dspam
%config(noreplace) /etc/mail/dspam/dspam.cfg
%config /etc/logrotate.d/pydspam
%attr(0775,root,root)%{_libexecdir}/pydspam
%attr(0755,dspam,dspam)%{htmldir}/dspam/dspamcgi.py
%dir %attr(0755,dspam,dspam)%{htmldir}/dspam
%config %{htmldir}/dspam/template.html
%config %{htmldir}/dspam/logo.gif
%config %{htmldir}/dspam/base.css
%{cgibin}/pydspam.cgi
%{python_sitearch}/Dspam.pyo
%{htmldir}/dspam/dspamcgi.pyc
%{htmldir}/dspam/dspamcgi.pyo

%files selinux
%doc pydspam.te
%{_datadir}/selinux/targeted/*

%post selinux
/usr/sbin/semodule -s targeted -i %{_datadir}/selinux/targeted/pydspam.pp \
	&>/dev/null || :

%postun selinux
if [ $1 -eq 0 ] ; then
/usr/sbin/semodule -s targeted -r pydspam &> /dev/null || :
fi

%changelog
* Sat Jul  7 2018 Stuart Gathman <stuart@gathman.org> 1.3.4-2
- Make /var/www/html/dspam owned by dspam:dspam to make suexec happy

* Mon Jul  2 2018 Stuart Gathman <stuart@gathman.org> 1.3.4-1
- Update selinux tag on /var/lib/dspam to match new dspam package

* Sat Jun 30 2018 Stuart Gathman <stuart@gathman.org> 1.3.3-2
- Require dspam-hash storage driver hardwired by Dspam.py

* Sat Jun 30 2018 Stuart Gathman <stuart@gathman.org> 1.3.3-1
- Align more with Fedora packaging standards

* Fri Sep 18 2015 Stuart Gathman <stuart@bmsi.com> 1.3.2-1
- Flag spams deleted from quarantine without discarding
- Detect messages added to quarantine after it was displayed

* Sun May 17 2015 Stuart Gathman <stuart@bmsi.com> 1.3.1-1
- Compute driver directory from --libdir CONFIGURE_ARG
- Add CONFIGURE_ARGS and PKGLIBDIR

* Sun Feb 15 2015 Stuart Gathman <stuart@bmsi.com> 1.3-3
- Fix selinux policy for alerts file for webui, add selinux subpackage.

* Sun Feb 15 2015 Stuart Gathman <stuart@bmsi.com> 1.3-2
- Clean up various typos and packaging problems.

* Thu Feb 05 2015 Stuart Gathman <stuart@bmsi.com> 1.3-1
- New dspam-3.10 API

* Sat Mar 05 2011 Stuart Gathman <stuart@bmsi.com> 1.1.12-1
- Ignore Resent headers
- Python 2.6 and python version specific packages

* Tue Jul 26 2005 Stuart Gathman <stuart@bmsi.com> 1.1.11-1
- Support quarantine rotation in dspamcgi.py
- add logrotate for quarantines

* Tue Jul 26 2005 Stuart Gathman <stuart@bmsi.com> 1.1.10-1
- Use passwd style update transaction lockfile (CGI)
- Case insensitive alerts (CGI)

* Tue Jul 26 2005 Stuart Gathman <stuart@bmsi.com> 1.1.9-1
- Forced result option for honeypot accounts

* Thu Apr 08 2004 Stuart Gathman <stuart@bmsi.com> 1.1.8-2
- Work with milter-0.8.0 and python-2.4

* Thu Apr 08 2004 Stuart Gathman <stuart@bmsi.com> 1.1.7-1
- dspamcgi.py: user and global configuration
- Dspam.py: handle tags changed to multiline HTML comments

* Fri Mar 12 2004 Stuart Gathman <stuart@bmsi.com> 1.1.6-1
- dspamcgi.py: sort by subject, decode subjects, handle large quarantine
- dspamcgi.py: handle missing alerts, quarantine
- Dspam.py: fix hang, unlock in wrong finally

* Thu Dec 18 2003 Stuart Gathman <stuart@bmsi.com> 1.1.5-1
- pydspam-1.1.5
- Move dspam-python to its own package
