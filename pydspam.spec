%ifos Linux
%define python python2
%define cgibin /var/www/cgi-bin
%define htmldir /var/www/html
%else
%define python python
%define cgibin /usr/local/www/cgi-bin
%define htmldir /Public
%endif

Summary: A Python wrapper for Dspam Bayesian spam filtering
Name: pydspam
Version: 1.1.6
Release: 1
Copyright: GPL
URL: http://www.bmsi.com/python/dspam.html
Group: Development/Libraries
Source: http://bmsi.com/python/pydspam-1.1.5.tar.gz
Buildroot: /var/tmp/pydspam-root
BuildRequires: %{python}-devel dspam-devel == 2.6.5.2
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
Install this if you wish to use DPSPAM from python.

%prep
%setup -q

%build
env CFLAGS="$RPM_OPT_FLAGS" %{python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT

# provide maintenance scripts
ETCDIR="$RPM_BUILD_ROOT/etc"
mkdir -p $ETCDIR/cron.hourly
cat >$ETCDIR/cron.hourly/dspam <<'EOF'
#!/bin/sh
cd /var/lib/dspam
exec >>reprocess.log 2>&1
/usr/local/bin/pydspam_process *.spam *.fp
EOF
chmod a+x $ETCDIR/cron.hourly/dspam

# install CGI script
CGIDIR="$RPM_BUILD_ROOT%{cgibin}"
HTMLDIR="$RPM_BUILD_ROOT%{htmldir}"
mkdir -p $HTMLDIR/dspam
mkdir -p $CGIDIR
%ifos aix4.1
# No suexec on our AIX installs
cat >$CGIDIR/pydspam.cgi <<'EOF'
#!/bin/sh
cd %{htmldir}/dspam
exec /usr/local/bin/python dspamcgi.py
EOF
%else
# Use suexec to run CGI
cat >$CGIDIR/pydspam.cgi <<'EOF'
#!/bin/sh
cd %{htmldir}/dspam
exec /usr/sbin/suexec dspam dspam dspamcgi.py
EOF
%endif
cp -p dspamcgi.py $HTMLDIR/dspam
chmod 0755 $HTMLDIR/dspam/dspamcgi.py $CGIDIR/pydspam.cgi

# install python module
%{python} setup.py install --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
while read file; do
  case "$file" in
  *.so) strip $RPM_BUILD_ROOT$file;;
  esac
done <INSTALLED_FILES

# install python utilities
mkdir -p $RPM_BUILD_ROOT/usr/local/bin
cp -p dspam_anal.py $RPM_BUILD_ROOT/usr/local/bin/pydspam_anal
cp -p dspam_corpus.py $RPM_BUILD_ROOT/usr/local/bin/pydspam_corpus
cp -p reprocess.py $RPM_BUILD_ROOT/usr/local/bin/pydspam_process

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
%doc dspam.html *dspam*.py Notes*
/etc/cron.hourly/dspam
%attr(0775,root,root)/usr/local/bin/pydspam_anal
%attr(0775,root,root)/usr/local/bin/pydspam_corpus
%attr(0775,root,root)/usr/local/bin/pydspam_process

%changelog
* Thu Dec 18 2003 Stuart Gathman <stuart@bmsi.com> 1.1.5-1
- pydspam-1.1.5
- Move dspam-python to its own package
