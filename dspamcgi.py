#!/usr/bin/python2.6

# DSPAM
# COPYRIGHT (C) 2003 NETWORK DWEEBS CORPORATION
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

from time import ctime,sleep,strptime,strftime,localtime
import sys
import StringIO
import os
import os.path
import cgi
import cgitb; cgitb.enable()
import mailbox
import re
import smtplib
import hashlib
from email.Header import decode_header
try: from ConfigParser import SafeConfigParser as ConfigParser
except: from ConfigParser import ConfigParser


## Configuration
#
CONFIG = {
  'userdir': "/var/lib/dspam",
  'me': "pydspam.cgi",
  'domain': "mail.bmsi.com",
  'dspam': "SMTP",	# send false positives via SMTP to ham@DOMAIN
# 'DSPAM': "/usr/local/bin/falsepositive",	# run script for FPs
  'large_scale': 'no',
  'viewspam_max': '500',
  'sort': 'subject'
}
#
## End Configuration

remote_user=None
USER=None
FORM=None
MAILBOX=None
VIEWSPAM_MAX = 500
VIEWSPAM_SORT = True
config = ConfigParser(CONFIG)
config.add_section('dspam')
config.add_section('cgi')

class PLock(object):
  def __init__(self,basename):
    self.basename = basename
    self.fp = None

  def lock(self,lockname=None):
    "Start an update transaction.  Return FILE to write new version."
    self.unlock()
    if not lockname:
      lockname = self.basename + '.lock'
    self.lockname = lockname
    st = os.stat(self.basename)
    u = os.umask(0002)
    try:
      fd = os.open(lockname,os.O_WRONLY+os.O_CREAT+os.O_EXCL,st.st_mode|0660)
    finally:
      os.umask(u)
    self.fp = os.fdopen(fd,'w')
    try:
      os.chown(self.lockname,-1,st.st_gid)
    except:
      self.unlock()
      raise
    return self.fp

  def wlock(self,lockname=None):
    "Wait until lock is free, then start an update transaction."
    while True:
      try:
        return self.lock(lockname)
      except OSError:
        sleep(2)

  def commit(self,backname=None):
    "Commit update transaction with optional backup file."
    if not self.fp:
      raise IOError,"File not locked"
    self.fp.close()
    self.fp = None
    if backname:
      try:
	os.remove(backname)
      except OSError:
	os.rename(self.lockname,self.basename)
	return
      os.link(self.basename,backname)
    os.rename(self.lockname,self.basename)

  def unlock(self):
    "Cancel update transaction."
    if self.fp:
      try:
        self.fp.close()
      except: pass
      self.fp = None
      os.remove(self.lockname)

def MailboxIdx(mb):
  """Return mailbox rotation index for user.
  >>> MailboxIdx('user.mbox')
  ('user.mbox', 0)
  >>> MailboxIdx('user.mbox.2')
  ('user.mbox', 2)
  """
  base,idx = os.path.splitext(mb)
  if idx == '.mbox': return mb,0
  try:
    return base,int(idx[1:])
  except:
    raise ValueError(mb)

def MailboxFromIdx(mb,idx):
  """Return mailbox rotation index for user.
  >>> MailboxFromIdx('user.mbox',0)
  'user.mbox'
  >>> MailboxFromIdx('user.mbox',2)
  'user.mbox.2'
  """
  if idx > 0:
    return '%s.%d' % (mb,idx)
  if idx < 0:
    raise ValueError(idx)
  return mb

def DoCommand():
  global remote_user,FORM,MAILBOX,USER,CONFIG,config
  global VIEWSPAM_MAX,VIEWSPAM_SORT
  remote_user = os.environ.get('REMOTE_USER','')
  if remote_user == '':
    error("System Error. I was unable to determine what username you are.")
  FORM = cgi.FieldStorage()
  userdir = config.get('dspam','userdir')
  config.read([os.path.join(userdir,'dspam.cfg')])
  userdir = config.get('dspam','userdir')

  if not config.getboolean('dspam','large_scale'):
    USER = os.path.join(userdir,'data',remote_user)
  elif len(remote_user) > 1:
    USER = os.path.join(userdir,
    	'data',remote_user[0:1],remote_user[1:2],remote_user,remote_user)
  else:
    USER = os.path.join(userdir,'data',remote_user,remote_user)

  config.read([USER + '.cfg'])
  CONFIG = dict(config.items('dspam'))

  VIEWSPAM_MAX = config.getint('cgi','viewspam_max')
  VIEWSPAM_SORT = config.get('cgi','sort').lower().startswith('sub')
  
  # put opposite sort in CONFIG defaults for easy toggle
  if VIEWSPAM_SORT:
    CONFIG['sort'] = 'arrival'
  else:
    CONFIG['sort'] = 'subject'
  CONFIG['viewspam_max'] = str(VIEWSPAM_MAX)

  idx = FORM.getfirst('MBOX_IDX','')
  if idx:
    try:
      CONFIG['mbox_idx'] = int(idx)
    except: pass
  if not CONFIG.has_key('mbox_idx'):
   CONFIG['mbox_idx'] = 0
  idx = CONFIG['mbox_idx']
  if idx:
    MAILBOX = '%s.mbox.%d' % (USER,idx)
  else:
    MAILBOX = USER + ".mbox"
    
  command = FORM.getfirst('COMMAND',"")
  if command == "": Welcome()
  elif command == "VIEW_SPAM": ViewSpam()
  elif command == "VIEW_ONE_SPAM": ViewOneSpam()
  elif command == "DELETE_SPAM": DeleteSpam()
  elif command == "NOTSPAM": NotSpam()
  elif command == "ADD_ALERT": AddAlert()
  elif command == "DELETE_ALERT": DeleteAlert()
  elif command == "SORT_SPAM": SortSpam()
  elif command == "CHANGE_MBOX": ChangeMbox()
  else: error("Invalid Command: %s" % command)

def getLastCount():
  cnt = FORM.getfirst('last_count',None)
  if cnt:
    try: cnt = int(cnt)
    except: cnt = None
  return cnt

def AddAlert():
  alert = FORM.getfirst('ALERT',"")
  if alert == "":
    error("No Alert Specified")
  FILE = open(USER+".alerts",'a')
  print >>FILE,alert
  FILE.close()
  Welcome()

def DeleteAlert():
  form_line = FORM.getfirst('line',"")
  if form_line == "":
    error("No Alert Specified")
  try:
    form_line = int(form_line)
    FILE = open(USER+".alerts",'r')
    alerts = FILE.readlines()
    del alerts[form_line]
    FILE.close()
    FILE = open(USER+".alerts",'w')
    FILE.writelines(alerts)
    FILE.close()
  except:
    error("Invalid Alert Selected")
  Welcome()

# Code for rfc822 rather than the email package because we only need
# the lowest level features (main headers and body), and spams don't play
# nice with the fancy new stuff.
def writeMsg(msg,fp):
  "Write rfc822 message to fp in unix mbox format."
  fp.write(msg.unixfrom)
  fp.write(''.join(msg.headers))
  fp.write('\n')
  msg.rewindbody()
  fp.write(msg.fp.read())

def messageID(msg):
  "Extract an ID suitable for selecting messages from a mailbox."
  m = hashlib.md5()
  for h in msg.headers:
    m.update(h)
  return m.hexdigest()

def getChecked(mid):
  "Return -1 unchecked, 1 checked, 0 not present"
  # Can't rely on returning '', so need second copy of every mid :-(
  a = FORM.getfirst('ALL-'+mid,'')
  if a != 'Y': return 0
  v = FORM.getfirst(mid,'')
  #print >>open('/tmp/pds','a'),mid,v,a
  if v == '': return -1
  return 1

def NotSpam(multi=False):
  if multi:
    message_id = None
  else:
    message_id = FORM.getfirst('MESSAGE_ID',"")
    if message_id == "":
      error("No Message ID Specified")
  FILE = open(MAILBOX,'r')
  mbox = mailbox.PortableUnixMailbox(FILE)
  remlist = {}
  for msg in mbox:
    mid = messageID(msg)
    if mid == message_id or not message_id and getChecked(mid) < 0:
      fpcmd = CONFIG['dspam']
      if fpcmd == 'SMTP':
	domain = CONFIG['domain']
	fromaddr = '%s@%s'%(remote_user,domain)
	toaddrs  = 'ham@%s'%domain
	server = smtplib.SMTP('localhost')
	#server.set_debuglevel(1)
	buff = StringIO.StringIO()
	del msg['X-Dspam-Status']
	writeMsg(msg,buff)
	try:
	  server.sendmail(fromaddr, toaddrs, buff.getvalue())
	  remlist[mid] = mid
	except smtplib.SMTPResponseException,x:
          #error('%d: %s'%(x.smtp_code,x.smtp_error))
          error(x)
	server.quit()
      else:
	PIPE = os.popen("%s -d %s --falsepositive"
	      % (CONFIG['dspam'],remote_user),'w')
	writeMsg(msg,PIPE)
	rc = PIPE.close()
	if rc: error(rc)
      if not multi: break
  FILE.close()
  if multi: return remlist
  if remlist:
    DeleteSpam(remlist)
  else:
    error("No message to delete")

def ViewOneSpam():
  message_id = FORM.getfirst('MESSAGE_ID',"")
  if message_id == "":
    error("No Message ID Specified")
  FILE = open(MAILBOX,'r')
  mbox = mailbox.PortableUnixMailbox(FILE)

  message = """
<FORM ACTION="%s">
<INPUT TYPE=HIDDEN NAME=MESSAGE_ID VALUE="%s">
<INPUT TYPE=HIDDEN NAME=COMMAND VALUE="NOTSPAM">
<INPUT TYPE=HIDDEN NAME=MBOX_IDX VALUE="%d">
<CENTER>
<INPUT TYPE=SUBMIT VALUE="THIS IS NOT SPAM!">
</CENTER>
</FORM>
<BR>
<PRE>
""" % (CONFIG['me'],message_id,CONFIG['mbox_idx'])
  for msg in mbox:
    if messageID(msg) == message_id:
      buff = StringIO.StringIO()
      writeMsg(msg,buff)
      message += cgi.escape(buff.getvalue(),quote=True)
  message += "</PRE>"
  output({ 'MESSAGE': message });

def ChangeMbox():
  global MAILBOX
  base,idx = MailboxIdx(MAILBOX)
  if FORM.getfirst('prev_mbox','') != '' and idx > 0:
    idx -= 1
  if FORM.getfirst('next_mbox','') != '':
    idx += 1
  mb = MailboxFromIdx(base,idx)
  if os.path.isfile(mb):
    CONFIG['mbox_idx'] = idx
    MAILBOX = mb
  ViewSpam()

def DeleteSpam(remlist=None):
  lock = PLock(MAILBOX)
  deleteAll = False
  if FORM.getfirst('delete_all',"") != "":
    lock.wlock()
    # FIXME: check for time,size change
    lock.commit()
  elif FORM.getfirst('notspam_all',"") != "":
    remlist = NotSpam(multi=True)
  # remlist is dict of mids that were successfully released
  buff = lock.wlock()
  try:
    FILE = open(MAILBOX,'r')
    mbox = mailbox.PortableUnixMailbox(FILE)
    try:
      maxcnt = int(FORM.getfirst('msg_cnt',str(VIEWSPAM_MAX)))
    except:
      maxcnt = VIEWSPAM_MAX
    cnt = 0
    msgcnt = 0
    for msg in mbox:
      cnt += 1
      message_id = messageID(msg)
      checked = getChecked(message_id)
      if checked < 0:
	# Mark unchecked message saved in case user saves it
	if cnt <= maxcnt:
	  msg['X-Dspam-Status'] = 'Keep' 
      elif checked > 0:
	# Mark checked message deleted so it doesn't show
	if cnt <= maxcnt:
	  del msg['X-Dspam-Status']
      if remlist is not None:
        # fully remove released messages
	if message_id not in remlist:
	  msgcnt += 1
	  writeMsg(msg,buff)
	continue
      status = msg.getheader('X-Status','')
      if not 'D' in status:
	if checked < 0:
	  msgcnt += 1
	elif checked > 0:
	  msg['X-Status'] = status + 'D'
      writeMsg(msg,buff)
    FILE.close()
    lock.commit()
  except:
    lock.unlock()
    raise
  print "Location: %s?COMMAND=VIEW_SPAM&MBOX_IDX=%d&last_count=%d\n"%(
	CONFIG['me'],CONFIG['mbox_idx'],msgcnt)

def trimString(s,maxlen):
  if len(s) <= maxlen:
    return s
  if maxlen > 3:
    return s[:maxlen-3] + "..."
  return s[:maxlen]

def getAlerts():
  try:
    FILE = open(USER+".alerts",'r')
    alerts = FILE.read().lower().splitlines()
    FILE.close()
  except IOError:
    alerts = []
  return alerts

def SortSpam():
  order = FORM.getfirst('ORDER',"arrival")
  max = FORM.getfirst('VIEWMAX',config.get('cgi','viewspam_max'))
  fp = open(USER + '.cfg','w')
  config.set('cgi','sort',order)
  config.set('cgi','viewspam_max',max)
  config.write(fp)
  fp.close()
  print "Location: %(me)s?COMMAND=VIEW_SPAM&MBOX_IDX=%(mbox_idx)d\n"%CONFIG
  
def ViewSpam():
  alerts = getAlerts()

  FILE = open(MAILBOX,'r')
  mbox = mailbox.PortableUnixMailbox(FILE)
  cnt = 0
  headinglist = []
  t = None
  for msg in mbox:
    if 'D' in msg.getheader('X-Status',''): continue
    if not cnt and msg.unixfrom:
      try:
	t = strptime(msg.unixfrom.split(None,2)[2].rstrip())
      except: pass
    cnt += 1
    for h in msg.headers:
      hl = h.lower()
      for al in alerts:
        if hl.find(al) > 0:
	  alert = True
	  break
      else:
        continue
      break
    else:
      alert = False

    heading = {}
    heading['From'] = trimString(msg.getheader('From',""),40)
    subj = msg.getheader('Subject',"")
    if subj == "":
      subj = "<None Specified>"
    else:
      h = decode_header(subj)
      if len(h) == 1 and len(h[0]) > 1 and h[0][1]:
	p = h[0]
	try:
	  u = unicode(p[0],p[1])
	  try:
	    subj = u.encode('us-ascii')
	  except LookupError:
	    pass
	  except UnicodeError:
	    subj = u.encode('utf8')
	except:
	  pass
    heading['Subject'] = trimString(subj,40)
    heading['Message-ID'] = messageID(msg)

    for key in heading.keys():
      if key != 'Message-ID': 
	heading[key] = cgi.escape(heading[key],quote=True)

    PAIRS = {
      'MESSAGE_ID': heading['Message-ID'],
      'COMMAND': "VIEW_ONE_SPAM",
      'MBOX_IDX': str(CONFIG['mbox_idx'])
    }
    heading['url'] = SafeVars(PAIRS)
    heading['alert'] = alert
    heading['start'] = msg.unixfrom.split(None,2)[2].strip()
    heading['ME'] = CONFIG['me']
    status = msg.getheader('X-Dspam-Status','')
    if status == '':
      heading['status'] = 'CHECKED'
    else:
      heading['status'] = ''

    headinglist.append((heading['Subject'],heading))
    if cnt >= VIEWSPAM_MAX: break

  buff = StringIO.StringIO()
  if t:
    s = strftime('%b %d',t)
    buff.write("<B>SPAM Blackhole: Email Quarantine for %s</B><BR>" % s)
  else:
    buff.write("<B>SPAM Blackhole: Email Quarantine</B><BR>")
  buff.write("""
<FORM ACTION="%(me)s" METHOD="POST">
<INPUT TYPE=HIDDEN NAME=COMMAND VALUE=SORT_SPAM>
<INPUT TYPE=HIDDEN NAME=ORDER VALUE="%(sort)s">
<INPUT TYPE=HIDDEN NAME=MBOX_IDX VALUE="%(mbox_idx)d">
<A HREF="%(me)s">Click Here to Return</A>
&nbsp;<INPUT TYPE=SUBMIT VALUE="Sort by %(sort)s" NAME=sort_spam> showing
<INPUT TYPE=TEXT NAME=VIEWMAX SIZE=4 VALUE="%(viewspam_max)s"> at a time.
</FORM>
<BR>
<FORM ACTION="%(me)s" METHOD="POST">
<INPUT TYPE=HIDDEN NAME=COMMAND VALUE=DELETE_SPAM>
<INPUT TYPE=HIDDEN NAME=MBOX_IDX VALUE="%(mbox_idx)d">
<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=0>
<TR><TD BGCOLOR=#000000><FONT COLOR=#FFFFFF SIZE=-1><B>&nbsp;DEL&nbsp;</B></FONT>&nbsp;&nbsp;</TD>
    <TD BGCOLOR=#000000><FONT COLOR=#FFFFFF SIZE=-1><B>&nbsp;SENT&nbsp;</B></FONT>&nbsp;&nbsp;</TD>
    <TD BGCOLOR=#000000><FONT COLOR=#FFFFFF SIZE=-1><B>&nbsp;FROM&nbsp;</B></FONT>&nbsp;&nbsp;</TD>
    <TD BGCOLOR=#000000><FONT COLOR=#FFFFFF SIZE=-1><B>&nbsp;SUBJECT&nbsp;</B></FONT>&nbsp;&nbsp;</TD>
</TR>
""" % CONFIG)
  if VIEWSPAM_SORT:
    headinglist.sort()
  bgcolor = None
  for subj,heading in headinglist:
    if heading['alert']: bgcolor = "FFFF00"
    elif bgcolor == "FFFFFF": bgcolor = "BBBBBB";
    else: bgcolor = "FFFFFF"
    heading['bgcolor'] = bgcolor
    buff.write("""
<TR>
 <TD BGCOLOR=#%(bgcolor)s><NOBR><FONT SIZE=-1>&nbsp;
   <INPUT TYPE=CHECKBOX %(status)s NAME="%(Message-ID)s">&nbsp;</FONT>
   <INPUT TYPE=HIDDEN VALUE="Y" NAME="ALL-%(Message-ID)s">
   &nbsp;&nbsp;</TD>
 <TD BGCOLOR=#%(bgcolor)s><NOBR><FONT SIZE=-1>&nbsp;%(start)s&nbsp;</FONT>
   &nbsp;&nbsp;</TD>
 <TD BGCOLOR=#%(bgcolor)s><NOBR><FONT SIZE=-1>&nbsp;%(From)s&nbsp;</FONT>
   &nbsp;&nbsp;</TD>
 <TD BGCOLOR=#%(bgcolor)s><NOBR><FONT SIZE=-1>&nbsp;<A HREF="%(ME)s?%(url)s">%(Subject)s</A>&nbsp;
   </FONT>&nbsp;&nbsp;</TD>
</TR>
""" % heading)

  msgcnt = getLastCount()
  if msgcnt:
    if msgcnt < cnt: msgcnt = cnt
    shown = "%d of %d messages shown." % (cnt,msgcnt)
  else:
    shown = ""
  base,idx = MailboxIdx(MAILBOX)
  if idx:
    prev = '&nbsp;<INPUT TYPE=SUBMIT VALUE="Next Day" Name=prev_mbox>'
  else:
    prev = ''
  if os.path.isfile(MailboxFromIdx(base,idx + 1)):
    next = '&nbsp;<INPUT TYPE=SUBMIT VALUE="Previous Day" Name=next_mbox>'
  else:
    next = ''
  buff.write("""
</TABLE>
<BR><INPUT TYPE=SUBMIT VALUE="Delete Checked">
<! &nbsp;<INPUT TYPE=SUBMIT VALUE="Delete All" NAME=delete_all>
&nbsp;<INPUT TYPE=SUBMIT VALUE="Unchecked Not Spam" NAME=notspam_all>
<INPUT TYPE=HIDDEN VALUE="%d" NAME=msg_cnt>
%s
</FORM>
<FORM ACTION="%s" METHOD="POST">
<INPUT TYPE=HIDDEN NAME=COMMAND VALUE=CHANGE_MBOX>
<INPUT TYPE=HIDDEN NAME=MBOX_IDX VALUE="%d">
%s %s
</FORM>
""" % (cnt,shown,CONFIG['me'],CONFIG['mbox_idx'],prev,next))
  output({'MESSAGE': buff.getvalue()})

def CountMsgs(fname):
  "Quickly count messages in quarantine.  Return cnt,time of first message"
  # If memory use is a problem for huge quarantines, loop over an mbox
  # instead.
  cnt = 0
  t = None
  try:
    FILE = open(fname,'r')
    eoh = True
    for ln in FILE:
      if ln.startswith('From '):
	if not cnt:
	  t = strptime(ln.split(None,2)[2].rstrip())
	cnt += 1
        eoh = False
      elif not eoh:
        # Don't count messages with 'D' in X-Status
        if ln.startswith('X-Status: '):
          if 'D' in ln:
            cnt -= 1
          eoh = True
        elif ln == '\n':
          eoh = True
    FILE.close()
    if not t:
      t = localtime(os.path.getmtime(fname))
  except IOError: 
    if not t:
      t = localtime()
  return cnt,t

def QuarantineList(base):
  "Return list of quarantines."
  idx = 0
  mb = MailboxFromIdx(base,idx)
  ls = []
  while os.path.isfile(mb) or not idx:
    f,t = CountMsgs(mb)
    s = strftime('%b %d',t)
    if f > 0:
      supp = """Quarantine for %s
    (<A HREF="%s?COMMAND=VIEW_SPAM&MBOX_IDX=%d&last_count=%d">%d messages</A>)
      """ % (s,CONFIG['me'],idx,f,f)
    else:
      supp = "Quarantine for %s is empty (%d messages)" % (s,f)
    ls.append(supp)
    idx += 1
    mb = MailboxFromIdx(base,idx)
  return ls

def Welcome():

  FILE = open(USER+".stats",'r')
  spam = FILE.readline()
  FILE.close()
  spam,innocent,misses,fp,cs,ci = map(int,spam.split(','))
  total = spam + innocent

  # Prepare Welcome Header
  if total > 0:
    ratio = "%3.2f" % (spam*100.0/total)
  else:
    ratio = '0'
  spam -= misses

  time = ctime() 
  REMOTE_USER = remote_user
  header = """
<TABLE BORDER=0 ALIGN=RIGHT>
<TR><TD>
  <TABLE BORDER=0>
  <TR><TD COLSPAN=2>Welcome, <I>%(REMOTE_USER)s</I>!</TD></TR>
  <TR><TD COLSPAN=2>It is <B>%(time)s</B></TD></TR>
  <TR><TD>DSPAM has caught </TD><TD><B>%(spam)s</B> spams</TD></TR>
  <TR><TD>...learned </TD><TD><B>%(misses)s</B> spams</TD></TR>
  <TR><TD>...scanned </TD><TD><B>%(total)s</B> total emails</TD></TR>
  <TR><TD>...with </TD><TD><B>%(fp)s</B> false positives</TD></TR>
  <TR><TD>Your SPAM Ratio is</TD><TD><B>%(ratio)s%%</B></TD></TR>
  </TABLE>
</TD></TR>
</TABLE>
""" % locals()

  supp = '<BR>\n'.join(QuarantineList(USER + ".mbox"))
    
  message = """
<B>My Quarantine</B><BR>
%(supp)s<BR>
<BR>
<B>My FP Alerts:</B><BR>
<TABLE BORDER=0>
""" % locals()

  alerts = getAlerts()
  line = 0
  for al in alerts:
    message += """<TR><TD>%s&nbsp;&nbsp;</TD><TD>[
      <A HREF="%s?COMMAND=DELETE_ALERT&line=%d">Delete</A>
    ]</TD></TR>\n""" % (
      cgi.escape(al),CONFIG['me'],line)
    line += 1

  message += """
</TABLE>
<FORM ACTION="%(me)s">
<INPUT TYPE=HIDDEN NAME=COMMAND VALUE=ADD_ALERT>
<INPUT NAME=ALERT> &nbsp;<INPUT TYPE=SUBMIT VALUE="Add Alert">
</FORM>
""" % CONFIG
  # FIXME: don't add when per user autotraining on.  Currently, 
  # only honeypot has autotraining.
  if remote_user != 'honeypot':
    message += """<BR><BR>
&nbsp;&nbsp;If you have encountered a SPAM that was not caught by DSPAM 
please forward it to <A HREF="mailto:spam@%(domain)s">spam@%(domain)s</A>
where it will be contextually analyzed by our software and added to your
statistical calculations.
""" % CONFIG

  output({'MESSAGE':message,'HEADER':header})

template_re = re.compile(r'\$([A-Z0-9]*)\$')

def output(DATA):
  print "Content-type: text/html\n"
  FILE = open('template.html','r')
  print template_re.sub(lambda m: DATA.get(m.expand(r'\1'),''),FILE.read())
  FILE.close()

def SafeVars(PAIRS):
  url = ''
  s = re.compile(r'([^A-Za-z0-9])')
  for key,value in PAIRS.items():
    value = s.sub(lambda m: '%%%02X'%ord(m.string[m.start()]),value)
    url += "%s=%s&" % (key,value)
  if url.endswith('&'): url = url[:-1]
  return url

def error(msg):
  output(
    { 'HEADER': "<B>AN ERROR HAS OCCURED</B>",
      'MESSAGE': """
The following error occured while trying to process your request: <BR>
<B>%s</B><BR>
<BR>
If this problem persists, please contact your administrator.
""" % msg }
  )
  sys.exit(0)

if __name__ == '__main__':
  DoCommand()
