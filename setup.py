import os
from distutils.core import setup, Extension

setup(name = "pydspam", version = "1.1.4",
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
	licence="GPL",
	url="http://www.bmsi.com/python/dspam.html",
	py_modules=["Dspam"],
	ext_modules=[
	  Extension("dspam", ["dspam.c"],
	    extra_objects=["../.libs/libdspam.a"],
	    libraries=["db"]
	  )
	])
