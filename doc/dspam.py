# Document dspam for Doxygen
#

## @package dspam
#
# A thin wrapper around libdspam.  Most users will not import
# dspam directly, but will instead import Dspam.
# This module gives you ultimate low level control
# from python.
#

## @name DSPAM flags for current operation context
# Select any combination when creating context with ctx.__init__.
##@{

  ## Signature is provided or requested.
  DSF_SIGNATURE           = 0x02
  ## Assign processor bias to unknown tokens.
  DSF_BIAS                = 0x04
  ## Apply Bayesian Noise Reduction logic.
  DSF_NOISE               = 0x08
  ## Use automatic whitelisting logic.
  DSF_WHITELIST           = 0x10
  ## Merge user/group data in memory.
  DSF_MERGED              = 0x20
  ## Unlearn the message.
  DSF_UNLEARN             = 0x80

##@}

## @name DSPAM Processing mode
# Select one when creating context with ctx.__init__
##@{

   ## Classify and learn the supplied message using whatever training
   # mode is specified.
   DSM_PROCESS	= 0
   ## Identifies that  the calling function is  from a utility, and no
   # operation will be requested.
   DSM_TOOLS	= 1
   ## Classify the  supplied  message  only, do not learn or update any
   # counters.
   DSM_CLASSIFY = 2
   DSM_NONE	= 0xff
##@}

## @name Classifications
# Select one for ctx.classification
##@{

   ## The message is spam.
   DSR_ISSPAM		= 1
   ## The message is not spam.
   DSR_ISINNOCENT	= 2
   ## No classification is supplied by the caller.
   DSR_NONE		= 0xff
##@}

## @name Source of Classification
# Select one for ctx.source
##@{

   ## Misclassification by dspam 
   DSS_ERROR		= 0	
   ## Corpus fed message 
   DSS_CORPUS		= 1	
   ## Message inoculation
   DSS_INOCULATION	= 2	
   ## No source - use only with DSR_NONE
   DSS_NONE		= 0xff	
##@}

## @name Tokenizers. 
# Select one for ctx.tokenizer
##@{

   ## Use WORD (uniGram) tokenizer
   DSZ_WORD	= 1	
   ## Use CHAIN (biGram) tokenizer
   DSZ_CHAIN	= 2	
   ## Use SBPH (Sparse Binary Polynomial Hashing) tokenizer
   DSZ_SBPH	= 3	
   ## Use OSB (Orthogonal Sparse biGram) tokenizer
   DSZ_OSB	= 4	
##@}

## @name Training Modes. 
# Select one for ctx.training_mode
##@{

   ## Train on everything
   DST_TEFT	= 0	
   ## Train on error
   DST_TOE	= 1	
   ## Train until mature
   DST_TUM	= 2	
   DST_NOTRAIN	= 0xFE
## @}

## @name Algorithms.  
# Set combination in ctx.algorithms
##@{

   ## Graham-Bayesian
   DSA_GRAHAM		= 1	
   ## Burton-Bayesian
   DSA_BURTON		= 2	
   ## Robinson's Geometric Mean Test
   DSA_ROBINSON		= 4	
   ## Fischer-Robinson's Chi-Square
   DSA_CHI_SQUARE	= 8	
   ## Naive Bayesian
   DSA_NAIVE		= 0x80	
## @}

## @name P-Value computations. 
# Used in ctx.algorithms
## @{

   ## Graham-Bayesian 
   DSP_GRAHAM		= 0x10	
   ## Robinson's Geometric Mean Test
   DSP_ROBINSON		= 0x20	
   ## Markov Weighted Technique
   DSP_MARKOV		= 0x40	
## @}

## Hold context for a DSPAM message operation
# Each context creates a new <code>DSPAM_CTX</code> struct within
# libdspam.  The dspam module in turn creates a ctx object.
# 
# Most application interaction with libdspam takes places via 
# the ctx object for the connection.  
#
class ctx(object):
  ## Initialize dspam context.  
  # @param username	dspam account the account applies to
  # @param mode		dspam processing mode: DSM_*
  # @param flags	dspam processing flags: DSF_*
  # @param group	dspam group
  # @param home		dspam home dir, libdspam compiled default if none.
  #	On RedHat/Fedora, this is <code>/var/lib/dspam</code>.
  def __init__(self,username,mode,flags=0,group=None,home=None): pass
    ## Result of DSPAM classification.
    self.result = DSR_NONE
    ## Callers classification.
    self.classification = DSR_NONE
    ## Source of callers classification.
    self.source = DSS_NONE
    ## Tokenizer algorithm.
    self.tokenizer = DSZ_WORD
    ## Classification algorithms to employ.  Use any combination
    # of DSA_* and DSP_* flags.
    self.algorithms = 0
    ## Training mode.  Use one of DST_* flags.
    self.training_mode = DST_TEFT
    ## Totals.
    # A tuple of 8 ints:
    # (spam_learned, innocent_learned,
    #  spam_misclassified, innocent_misclassified,
    #  spam_corpusfed, innocent_corpusfed,
    #  spam_classified, innocent_classified)
    self.totals = (0,0,0,0,0,0,0,0)
    ## Probability.
    # The probability that the message is spam according to libdspam.
    self.probability = 0.0
    ## Factors.
    # A list of token_name,weight tuples.  These are the factors used
    # by dspam to compute the probability.
    self.factors = []

  ## Calls <code>dspam_process(DSPAM_CTX ctx, const char *msg)</code>
  # @param msg the email message to process
  # @param sig a signature obtained from self.signature, or None
  def process(self,msg,sig=None): pass

  ## Add configuration attribute to context.  Context configuration controls
  # the tokenizer, storage driver, and other aspects of DSPAM for this context.
  # @param key	str key
  # @param val	str value
  def addattribute(self,key,val): pass

  ## Clear configuration attributes from this context.
  def clearattributes(self): pass

  ## Attaches storage driver to context.  Driver specific context configuration
  # should be done before attaching the driver.
  # @param dbh  a storage handle obtained from the driver ctx in a driver
  # specific way so it can be reused, or None
  def attach(self,dbh=None): pass

  ## Store a signature using the attached storage driver.  The tag
  # should be suitable for a filename.
  # @param tag unique tag assigned to the signature
  # @param sig Binary signature obtained from self.signature
  def set_signature(self,tag,sig): pass

  ## Retrieve a signature stored using the attached storage driver.  
  # Throws an exception if the tag is not present.  Use verify_signature to
  # check first.
  # @param tag unique tag assigned to the signature
  # @return the tag retreived
  def get_signature(self,tag): pass

  ## Delete a signature stored using the attached storage driver.  
  # Throws an exception if the tag is not present.  
  # @param tag unique tag assigned to the signature
  def delete_signature(self,tag): pass

  ## Verify a signature stored using the attached storage driver.  
  # Use verify_signature to check first.
  # @param tag unique tag assigned to the signature
  # @return True if the tag still exists in storage
  def verify_signature(self,tag): pass

  ## Detaches storage driver from context.  
  def detach(self): pass

  ## Tokenize the header and body of a message, and return a dictionary
  # of token,freq tuples by hash.
  def tokenize(self,header,body): pass

  ## Destroy context, releasing all resources.
  def destroy(self): pass

class error(Exception): pass

## Return path of user or group specific file.
# This calls the internal libdspam function <code>_ds_userdir_path()</code>,
# which has compile time options for how the path name is computed
# (for example LARGEFILE, HOMEDIR, DOMAINSCALE). If the
# extension is None, the user directory is returned, otherwise the path
# of a user file is returned.  For a user file
# with no extension, use an empty string for the extension.

# @param home The dspam base dir - normally what is passed to dspam.ctx.
# @param user The user or group name that forms the base of the file.
# @param ext The filename extension, or '' or None
def userdir(home,user,ext=None): pass

## Get fnctl lock for open file using libdspam conventions.
# @param fd the fileno of an open file
def get_fcntl_lock(fd): pass

## Free the fnctl lock for an open file using libdspam conventions.
# @param fd the fileno of an open file
def free_fcntl_lock(fd): pass

## Set debugging output mode.  Mode 2 is more efficient, but mode 1
# ensures that you see all the output.  This only works if libdspam
# was configured with --enable-debug when compiled, and pydspam
# has DEBUG uncommented at the top.  I will recommend to upstream
# that DO_DEBUG be always exported - or perhaps dspam_set_debug(int).

# @param mode 0 - off, 1 - flush after every output, 2 - no flush
def set_debug(mode): pass

## Set verified_user flag.  Set to true for libdspam to autocreate
# user directories, and other behaviour I haven't speced out yet.
# I defaulted this to True, since that is the dspam default
# when external lookup is not configured.
def set_verified_user(flag): pass

## Initialize libdspam.  Currently this just means dynamically
# loading the storage driver.
# The driver path can be None only if it was statically configured
# when libdspam was compiled.
#
# libdspam_init calls <code>dspam_init_driver(NULL)</code>, and will
# actually pass a <code>DRIVER_CTX *</code> when I figure out the
# multi-threading API.
# @param driver	str pathname to storage driver
def libdspam_init(driver): pass

## Shutdown libdspam.  Currently this just means unloading the storage driver,
# unless statically configured at libdspam compile time.
#
# libdspam_shutdown calls <code>dspam_shutdown_driver(NULL)</code>,
# with the <code>DRIVER_CTX *</code> used in libdspam_init.
def libdspam_shutdown(): pass

## The compile time libdspam version.
# Python code might need to deal with several iterations of the libdspam API.
# This module constant is a tuple with the major, minor, and patch
# level of the library API at the time pydspam was compiled.
# This is <b>not</b> necessarily the same as the version of dspam running.
LIBDSPAM_VERSION = (3,6,0)
