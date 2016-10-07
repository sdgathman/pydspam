import os
from distutils.core import setup, Extension

setup(name = "pydspam", version = "1.3.2",
	description="Python interface to libdspam",
	long_description="""\
This is a python extension module to enable python scripts to
use libdspam functionality.  A higher level wrapper handles a
signature database and quarantine mbox in a user directory.

This release updates pydspam for dspam-3.10.2. Because the libdspam API changed
drastically since dspam-2.6, this is considered a Beta release. I do have it
running on several production systems with no problems.
""",
	author="Stuart D. Gathman",
	author_email="stuart@gathman.org",
	maintainer="Stuart D. Gathman",
	maintainer_email="stuart@gathman.org",
	license="GPL",
	url="http://www.bmsi.com/python/dspam.html",
	py_modules=["Dspam"],
	ext_modules=[
	  Extension("dspam", ["dspam.c"],
	    libraries=["dspam"]
	  )
	],
	classifiers = [
	  'Development Status :: 4 - Beta',
	  'Environment :: No Input/Output (Daemon)',
	  'Intended Audience :: System Administrators',
	  'License :: OSI Approved :: GNU General Public License (GPL)',
	  'Natural Language :: English',
	  'Operating System :: OS Independent',
	  'Programming Language :: Python',
	  'Topic :: Communications :: Email :: Filters'
	]
)
