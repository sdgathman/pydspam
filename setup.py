import os
from distutils.core import setup, Extension

setup(name = "dspam", version = "2.6.2",
	description="Python interface to libdspam",
	long_description="""\
This is a python extension module to enable python scripts to
use libdspam functionality.  
""",
	author="Stuart D. Gathman",
	author_email="stuart@bmsi.com",
	maintainer="Stuart D. Gathman",
	maintainer_email="stuart@bmsi.com",
	licence="GPL",
	url="http://www.bmsi.com/python/dspam.html",
	ext_modules=[
	  Extension("dspam", ["dspam.c"],
	    extra_objects=["../.libs/libdspam.a"],
	    libraries=["db-3.2"]
	  )
	])
