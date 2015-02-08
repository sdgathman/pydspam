## @mainpage Using libdspam from Python
#
# At the lowest level, the <code>dspam</code> module provides a thin wrapper
# around the <a href="http://wiki.ledhed.net/index.php/DSpam_README"> 
# libdspam API</a>.  This API lets you classify emails and train the 
# dictionaries in a custom integrated manner.
# 
# At the next level, the <code>Dspam</code> module (note the case difference)
# provides a Python friendly object oriented wrapper for the low level API.  
#
# @section threading
#
# The libdspam library which pydspam wraps is threadsafe.  However, some
# of the storage driver plugins are <b>not</b> threadsafe.
