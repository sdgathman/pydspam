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
# 
# @section datatypes
# 
# <ul>
# <li> message - bytes, the contents of an email including header
#   and body as it would be received over SMTP
# <li> signature - bytes, libdspam parses the message into tokens,
#   and creates a signature which is a representation of the tokens,
#   currently a hash and truncated count for each token.  The signature
#   contains the information to train or retrain the bayesian filter
#   for a message.
# <li> signature_tag - str, a unique tag assigned to a signature.  The
#   signature is stored in a database under this key.  The tag is also
#   inserted into a message so that the signature can be found to reliably
#   retrain for a message even when the message has been modified from
#   what libdspam parsed by subsequent filtering.
# </ul>
