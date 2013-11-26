#!/usr/bin/python

import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "python"))
import trap
import unirec
from optparse import OptionParser

import smtplib
import email
import time

""""
Email reporter module

TODO:
- print warning if template contains invalid references
- limit max N messages sent per hour
"""


module_info = trap.CreateModuleInfo(
   "Email reporter", # Module name
"""\
Each UniRec record received is transformed to an email of specified 
template and send to specified address.

Usage:
   python email_reporter.py -i "ifc_spec" [options] CONFIG_FILE 

Parameters:
   CONFIG_FILE    File with configuration. It should contain information about 
                  SMTP server to connect to and a teplate of the message.
                  Format of this file is given below.
   -d, --dry-run  Dry-run mode - nothing is sent, messages are printed to stdout
                  instead.
   --skip-smtp-test  By default, the module tries to connect to specified SMTP 
                     server on startup to check that the connection (and login
                     credentials, if specified) works. You can skip the test 
                     using this option.
"""
#   --limit=N  Set maximal number of emails sent per hour. If more records arrive on input,...
"""\

The config file has two sections. First, there is specification of UniRec
template, SMTP server to be used, optionally login credentials and so on.
Format of this section is given by example below.
You can use comments (start them with '#') in this section. 

The second section starts after a blank line and it contains template of
an email message in RFC2822 format. That is: headers (e.g. From, To, Subject),
blank line and message body. The "Date:" header is added automatically.
The template may contain references to fields of 
UniRec record which will be substituted by corresponding values in each message.
References are made using '$' followed by name of the field.

An example of config file:
  unirec=<CAT_ALERT>
  server=smtp.example.com
  port=25  # optional, default: 25
  starttls=1 # optional, default: 0
  login=username:password  # optional, default: no login

  From: NEMEA <nemea@example.com>
  To: Main Recipient <recipient1@example.com>
  Cc: <recipient2@example.com>
  Bcc: <recipient4@example.com>
  Subject: [Nemea-alert] $SRC_IP sent a picture of cat

  NEMEA system has detected a picture of cat being sent over the internet.
  Details:
    Source:            $SRC_IP
    Destination:       $DST_IP
    File name:         $FILENAME
    Time of detection: $TIMESTAMP
  -----
  This is automatically generated email, don't reply.
  You can contact Nemea administrators at nobody@example.com.
""",
   1, # Number of input interfaces
   0  # Number of output interfaces
)


# ********** Parse parameters **********
parser = OptionParser()
parser.add_option("-d", "--dry-run", action="store_true")
parser.add_option("--skip-smtp-test", action="store_true")

# Extract TRAP parameters
try:
   ifc_spec = trap.parseParams(sys.argv, module_info)
except trap.EBadParams, e:
   if "Interface specifier (option -i) not found." in str(e):
      print 'Usage:\n   python email_reporter.py -i "ifc_spec" [options] CONFIG_FILE'
      exit(1)
   else:
      raise e

# Parse the other parameters
opt, args = parser.parse_args()

if len(args) != 1:
   print 'Usage:\n   python email_reporter.py -i "ifc_spec" [options] CONFIG_FILE'
   exit(1) 

config_file = args[0]

# ********** Initialize module **********
trap.init(module_info, ifc_spec)
trap.registerDefaultSignalHandler()

# Dafaults
unirecfmt = None
server = None
port = 25
starttls = False
login = None

# ********** Parse config file **********
config, msg_header, msg_body = open(config_file, "r").read().split("\n\n", 2)

for i,line in enumerate(config.splitlines()):
   # Cut off comments and leading/trailing whitespaces
   line = line.partition('#')[0].strip() # FIXME: in this way, password can't contain '#'
   if line == "":
      continue

   var,_,val = line.partition('=')
   if val == "":
      print >> sys.stderr, 'Error in config file (line %i): Each line in first section must have format "varibale=value".' % i
      exit(1)
   var = var.strip()
   val = val.strip()

   if var == "unirec":
      unirecfmt = val
   elif var == "server":
      server = val
   elif var == "port":
      port = int(val)
   elif var == "starttls":
      starttls = (val == "1" or val.lower() == "true")
   elif var == "login":
      login = val.partition(':')
      login = (login[0], login[2])
   else:
      print >> sys.stderr, 'Error in config file (line %i): Unknown variable "%s".' % (i,var)
      exit(1)

if unirecfmt is None:
   print >> sys.stderr, 'Error in config file: UniRec template must be set ("unirec=..." not found).'
   exit(1)
if server is None:
   print >> sys.stderr, 'Error in config file: SMTP server must be set ("server=..." not found).'
   exit(1)

# Create class for incoming UniRec records
UniRecType = unirec.CreateTemplate("UniRecType", unirecfmt)


# ********** Parse email template **********
sender = None
recipients = []

headers = email.message_from_string(msg_header)

# Find sender address
if 'from' in headers:
   sender = headers['from']
else:
   print >> sys.stderr, 'Error in message template: "From:" header not found.'
   exit(1)

# Find all recipients
recipients.extend(headers.get_all('to', []))
recipients.extend(headers.get_all('cc', []))
recipients.extend(headers.get_all('bcc', []))
if len(recipients) == 0:
   print >> sys.stderr, 'Error in message template: No recipient (headers "To:", "Cc:" or "Bcc:") found.'
   exit(1)

# Remove Bcc headers
del headers['bcc']

# Add Date header
headers.add_header("Date", "$_DATETIME_") # $_DATETIME_ will be replaced by current date-time before a message is sent


if trap.getVerboseLevel() >= 0:
   print "Information parsed from config:"
   print "  UniRec template:", repr(unirecfmt)
   print "  SMTP server address:", repr(server)
   print "  SMTP server port:", repr(port)
   print "  Use STARTTLS:", repr(starttls)
   print "  Login credentials:", repr(login)
   print "  Sender:", repr(sender)
   print "  Recipients:", repr(recipients)


msg_template = headers.as_string() + msg_body

msg_template = msg_template.replace("%", "%%")
# Get names of all UniRec fields in the template and sort from the longest to
# shortest (to solve a problem when there are fields ABC and ABCD and we should
# substitute $ABCD)
fields = UniRecType.fields()
fields.sort(lambda a,b: cmp(len(a),len(b)), reverse=True)
fields.append('_DATETIME_')
# Substitute all occurences of '$FIELD_NAME' by '%(FIELD_NAME)s'
for f in fields:
   msg_template = msg_template.replace("$"+f, "%("+f+")s")


if trap.getVerboseLevel() >= 0:
   print fields
   print "Message template:"
   print msg_template
   print "--------------------"

# ********** Test connection to the server **********
if not opt.skip_smtp_test and not opt.dry_run:
   s = smtplib.SMTP()
   if trap.getVerboseLevel() >= 0:
      s.set_debuglevel(True)
      print "Trying to connect to the server..."
   try:
      s.connect(server, port)
   except smtplib.socket.error, e:
      print >> sys.stderr, "Error when trying to connect to '%s:%i':" % (server, port)
      print >> sys.stderr, e
      exit(1)
   if starttls:
      s.starttls()
   if login:
      s.login(login[0], login[1])
   s.quit()


# ********** Main loop **********
while not trap.stop:
   # *** Read data from input interface ***
   try:
      data = trap.getData(0x1, trap.WAIT)
   except trap.ETerminated:
      break

   # Check for "end-of-stream" record
   if len(data) <= 1:
      break

   # Convert data to UniRec
   rec = UniRecType(data)

   # *** Prepare email body ***
   unirec_dict = rec.todict()
   unirec_dict['_DATETIME_'] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
   message = msg_template % unirec_dict


   # *** Send email ***
   if not opt.dry_run:
      s = smtplib.SMTP()
      if trap.getVerboseLevel() >= 0:
         s.set_debuglevel(True)
      try:
         s.connect(server, port)
      except smtplib.socket.error, e:
         print >> sys.stderr, "Error when trying to connect to '%s:%i':" % (server, port)
         print >> sys.stderr, e
         exit(1)
      if starttls:
         s.starttls()
      if login:
         s.login(login[0], login[1])
      s.sendmail(sender, recipients, message)
      s.quit()
   else:
      print "-----------------------------------------------------------------------"
      print "TIME:", time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
      print "FROM:", sender
      print "RECIPIENTS:", ', '.join(recipients)
      print "              ----- MESSAGE STARTS ON THE NEXT LINE -----              "
      print message

