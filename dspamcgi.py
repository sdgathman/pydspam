#!/usr/bin/python2

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

from time import ctime
import sys
import StringIO
import os
import os.path
import cgi
#import cgitb; cgitb.enable()
import mailbox
import re

## Configuration
#
CONFIG = {
  'USERDIR': "/etc/mail/dspam",
  'ME': "pydspam.cgi",
  'DOMAIN': "mail.bmsi.com",
  'DSPAM': "/usr/local/bin/falsepositive",
  'LARGE_SCALE': 0
}
#
## End Configuration

def DoCommand():
  global remote_user,FORM,MAILBOX,USER
  remote_user = os.environ.get('REMOTE_USER','')
  if remote_user == '':
    error("System Error. I was unable to determine what username you are.")
  FORM = cgi.FieldStorage()
  userdir = CONFIG['USERDIR']

  if CONFIG['LARGE_SCALE'] == 0:
    USER = os.path.join(userdir,remote_user)
  elif len(remote_user) > 1:
    USER = os.path.join(userdir,remote_user[0:1],remote_user[1:1],remote_user)
  else:
    USER = os.path.join(userdir,remote_user,remote_user)

  MAILBOX = USER + ".mbox"

  command = FORM.getfirst('COMMAND',"")
  if command == "": Welcome()
  elif command == "VIEW_SPAM": ViewSpam()
  elif command == "VIEW_ONE_SPAM": ViewOneSpam()
  elif command == "DELETE_SPAM": DeleteSpam()
  elif command == "NOTSPAM": NotSpam()
  elif command == "ADD_ALERT": AddAlert()
  elif command == "DELETE_ALERT": DeleteAlert()
  else: error("Invalid Command: %s" % command)

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
  message_id = msg.getheader('Message-ID',"")
  if message_id == "":
    message_id = msg.getheader('Subject',"")
  return message_id.replace('"','').replace("'","").replace('\n','')

def NotSpam():
  message_id = FORM.getfirst('MESSAGE_ID',"")
  if message_id == "":
    error("No Message ID Specified")
  FILE = open(MAILBOX,'r')
  mbox = mailbox.PortableUnixMailbox(FILE)
  for msg in mbox:
    if messageID(msg) == message_id:
      PIPE = os.popen("%s -d %s --falsepositive"
	    % (CONFIG['DSPAM'],remote_user),'w')
      writeMsg(msg,PIPE)
      rc = PIPE.close()
      if rc: error(rc)
      break
  FILE.close()
  DeleteSpam([message_id])
  print "Location: %s?COMMAND=VIEW_SPAM\n" % CONFIG['ME']

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
<CENTER>
<INPUT TYPE=SUBMIT VALUE="THIS IS NOT SPAM!">
</CENTER>
</FORM>
<BR>
<PRE>
""" % (CONFIG['ME'],message_id)
  for msg in mbox:
    if messageID(msg) == message_id:
      buff = StringIO.StringIO()
      writeMsg(msg,buff)
      message += cgi.escape(buff.getvalue(),quote=True)
  message += "</PRE>"
  output({ 'MESSAGE': message });

def DeleteSpam(remlist=None):
  if FORM.getfirst('delete_all',"") != "":
    # FIXME: dangerous, could lose messages added since mailbox read!
    open(MAILBOX,'w').close()
  FILE = open(MAILBOX,'r')
  mbox = mailbox.PortableUnixMailbox(FILE)
  buff = StringIO.StringIO()
  for msg in mbox:
    message_id = messageID(msg)
    #print >>sys.stderr,repr(message_id)
    #print >>sys.stderr,FORM.getvalue(message_id,"")
    if remlist:
      if not message_id in remlist:
        writeMsg(msg,buff)
    elif FORM.getfirst(message_id,"") == "":
      writeMsg(msg,buff)
  #print >>sys.stderr,FORM
  FILE.close()
  FILE = open(MAILBOX,'w')
  FILE.write(buff.getvalue())
  print "Location: %s?COMMAND=VIEW_SPAM\n" % CONFIG['ME']

def trimString(s,maxlen):
  if len(s) <= maxlen:
    return s
  if maxlen > 3:
    return s[:maxlen-3] + "..."
  return s[:maxlen]

def ViewSpam():
  FILE = open(USER+".alerts",'r')
  alerts = FILE.read().splitlines()
  FILE.close()

  buff = StringIO.StringIO()
  buff.write("""
<FORM ACTION="%(ME)s" METHOD="POST">
<InPUT TYPE=HIDDEN NAME=COMMAND VALUE=DELETE_SPAM>
<B>SPAM Blackhole: Email Quarantine</B><BR>
<A HREF="%(ME)s">Click Here to Return</A><BR>
<BR>
<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=0>
<TR><TD BGCOLOR=#000000><FONT COLOR=#FFFFFF SIZE=-1><B>&nbsp;DEL&nbsp;</B></FONT>&nbsp;&nbsp;</TD>
    <TD BGCOLOR=#000000><FONT COLOR=#FFFFFF SIZE=-1><B>&nbsp;SENT&nbsp;</B></FONT>&nbsp;&nbsp;</TD>
    <TD BGCOLOR=#000000><FONT COLOR=#FFFFFF SIZE=-1><B>&nbsp;FROM&nbsp;</B></FONT>&nbsp;&nbsp;</TD>
    <TD BGCOLOR=#000000><FONT COLOR=#FFFFFF SIZE=-1><B>&nbsp;SUBJECT&nbsp;</B></FONT>&nbsp;&nbsp;</TD>
</TR>
""" % CONFIG)

  FILE = open(MAILBOX,'r')
  mbox = mailbox.PortableUnixMailbox(FILE)
  bgcolor = None
  for msg in mbox:
    #my(%heading, $start, $alert);
    alert = False
    for h in msg.headers:
      for al in alerts:
        if h.find(al) > 0:
          alert = True
	  break
      if alert: break
    if alert: bgcolor = "FFFF00"
    elif bgcolor == "FFFFFF": bgcolor = "BBBBBB";
    else: bgcolor = "FFFFFF"

    heading = {}
    heading['Subject'] = trimString(msg.getheader('Subject',""),40)
    heading['From'] = trimString(msg.getheader('From',""),40)
    if heading['Subject'] == "":
      heading['Subject'] = "<None Specified>"

    heading['Message-ID'] = messageID(msg)

    for key in heading.keys():
      if key != 'Message-ID': 
	heading[key] = cgi.escape(heading[key],quote=True)

    PAIRS = {
      'MESSAGE_ID': heading['Message-ID'],
      'COMMAND': "VIEW_ONE_SPAM"
    }
    heading['url'] = SafeVars(PAIRS)
    heading['bgcolor'] = bgcolor
    heading['start'] = msg.unixfrom.split(None,2)[2].strip()
    heading['ME'] = CONFIG['ME']

    buff.write("""
<TR>
 <TD BGCOLOR=#%(bgcolor)s><NOBR><FONT SIZE=-1>&nbsp;
   <INPUT TYPE=CHECKBOX CHECKED NAME="%(Message-ID)s">&nbsp;</B></FONT>
   &nbsp;&nbsp;</TD>
 <TD BGCOLOR=#%(bgcolor)s><NOBR><FONT SIZE=-1>&nbsp;%(start)s&nbsp;</B></FONT>
   &nbsp;&nbsp;</TD>
 <TD BGCOLOR=#%(bgcolor)s><NOBR><FONT SIZE=-1>&nbsp;%(From)s&nbsp;</B></FONT>
   &nbsp;&nbsp;</TD>
 <TD BGCOLOR=#%(bgcolor)s><NOBR><FONT SIZE=-1>&nbsp;<A HREF="%(ME)s?%(url)s">%(Subject)s</A>&nbsp;</B>
   </FONT>&nbsp;&nbsp;</TD>
</TR>
""" % heading)

  buff.write("""
</TABLE>
<BR><INPUT TYPE=SUBMIT VALUE="Delete Checked">
<! &nbsp;<INPUT TYPE=SUBMIT VALUE="Delete All" NAME=delete_all>
</FORM>
""")
  output({'MESSAGE': buff.getvalue()})

def CountMsgs(fname):
  "Quickly count messages in quarantine."  
  # If memory use is a problem for huge quarantines, loop over an mbox
  # instead.
  FILE = open(fname,'r')
  s = FILE.read()
  FILE.close()
  if s: return len(s.split('\nFrom '))
  return 0

def Welcome():

  FILE = open(USER+".stats",'r')
  spam = FILE.readline()
  FILE.close()
  spam,innocent,misses,fp = map(int,spam.split(','))

  # Prepare Welcome Header
  if spam + innocent > 0:
    ratio = "%3.2f" % (spam*100.0/(spam+innocent))
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
  <TR><TD>...scanned </TD><TD><B>%(innocent)s</B> innocent emails</TD></TR>
  <TR><TD>...with </TD><TD><B>%(fp)s</B> false positives</TD></TR>
  <TR><TD>Your SPAM Ratio is</TD><TD><B>%(ratio)s%%</B></TD></TR>
  </TABLE>
</TD></TR>
</TABLE>
""" % locals()

  supp = None
  f = CountMsgs(MAILBOX)

  if f > 0:
    supp = """You have Quarantined Mail
      (<A HREF="%s?COMMAND=VIEW_SPAM">%d messages</A>)""" % (CONFIG['ME'],f)
  else:
    supp = "Your Quarantine is empty (%d messages)" % f

  message = """
<B>My Quarantine</B><BR>
%(supp)s<BR>
<BR>
<B>My FP Alerts:</B><BR>
<TABLE BORDER=0>
""" % locals()

  FILE = open(USER+".alerts",'r')
  alerts = FILE.read().splitlines()
  FILE.close()
  line = 0
  for al in alerts:
    message += """<TR><TD>%s&nbsp;&nbsp;</TD><TD>[
      <A HREF="%s?COMMAND=DELETE_ALERT&line=%d">Delete</A>
    ]</TD></TR>\n""" % (
      cgi.escape(al),CONFIG['ME'],line)
    line += 1

  message += """
</TABLE>
<FORM ACTION="%(ME)s">
<INPUT TYPE=HIDDEN NAME=COMMAND VALUE=ADD_ALERT>
<INPUT NAME=ALERT> &nbsp;<INPUT TYPE=SUBMIT VALUE="Add Alert">
</FORM>
<BR><BR>
&nbsp;&nbsp;If you have encountered a SPAM that was not caught by DSPAM 
please forward it to <A HREF="mailto:spam@%(DOMAIN)s">spam@%(DOMAIN)s</A>
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
