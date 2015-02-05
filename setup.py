import os
from distutils.core import setup, Extension

setup(name = "pydspam", version = "1.1.11",
	description="Python interface to libdspam",
	long_description="""\
This is a python extension module to enable python scripts to
use libdspam functionality.  A higher level wrapper handles a
signature database and quarantine mbox in a user directory.
""",
	author="Stuart D. Gathman",
	author_email="stuart@bmsi.com",
	maintainer="Stuart D. Gathman",
	maintainer_email="stuart@bmsi.com",
	license="GPL",
	url="http://www.bmsi.com/python/dspam.html",
	py_modules=["Dspam"],
	ext_modules=[
	  Extension("dspam", ["dspam.c"],
	    libraries=["dspam"]
	  )
	],
	classifiers = [
	  'Development Status :: 5 - Production/Stable',
	  'Environment :: No Input/Output (Daemon)',
	  'Intended Audience :: System Administrators',
	  'License :: OSI Approved :: GNU General Public License (GPL)',
	  'Natural Language :: English',
	  'Operating System :: OS Independent',
	  'Programming Language :: Python',
	  'Topic :: Communications :: Email :: Filters'
	]
)
