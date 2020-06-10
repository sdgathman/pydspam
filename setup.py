import os
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(name = "pydspam", version = "1.4.0",
	description="Python interface to libdspam",
	long_description=long_description,
	author="Stuart D. Gathman",
	author_email="stuart@gathman.org",
	maintainer="Stuart D. Gathman",
	maintainer_email="stuart@gathman.org",
	license="GPL",
	url="https://github.com/sdgathman/pydspam",
	py_modules=["Dspam"],
	ext_modules=[
	  setuptools.Extension("dspam", ["dspam.c"],
	    libraries=["dspam"],
	    define_macros = [ ('LOGDIR',"/var/log/dspam"),
                              ('CONFIG_DEFAULT',"/etc/dspam.conf") ],
            # save lots of debugging time testing rfc2553 compliance
            extra_compile_args = [ "-Werror=implicit-function-declaration" ]
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
