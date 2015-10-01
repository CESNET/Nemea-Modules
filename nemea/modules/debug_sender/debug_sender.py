#!/usr/bin/python
#
# Copyright (C) 2013-2015 CESNET
#
# LICENSE TERMS
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name of the Company nor the names of its contributors
#    may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# ALTERNATIVELY, provided that this notice is retained in full, this
# product may be distributed under the terms of the GNU General Public
# License (GPL) version 2 or later, in which case the provisions
# of the GPL apply INSTEAD OF those given above.
#
# This software is provided ``as is'', and any express or implied
# warranties, including, but not limited to, the implied warranties of
# merchantability and fitness for a particular purpose are disclaimed.
# In no event shall the company or contributors be liable for any
# direct, indirect, incidental, special, exemplary, or consequential
# damages (including, but not limited to, procurement of substitute
# goods or services; loss of use, data, or profits; or business
# interruption) however caused and on any theory of liability, whether
# in contract, strict liability, or tort (including negligence or
# otherwise) arising in any way out of the use of this software, even
# if advised of the possibility of such damage.

import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "python"))
import trap
import unirec
from unirec import Timestamp, IPAddr
import readline
from re import match

module_info = trap.CreateModuleInfo(
   name = "DebugSender",
   description = """\
This module allows to manually send arbitrary UniRec records to a TRAP
interface. You have to specify UniRec format at startup, everything other is
done interactively by writing simple commands.

Usage:
   python debug_sender.py -i IFC_SPEC UNIREC_FORMAT
""",
   num_ifc_in = 0,
   num_ifc_out = 1
)

# ----------------------------------------------------------------------------

def init_trap():
   trap.init(module_info, ifc_spec)
   trap.registerDefaultSignalHandler()
   trap.ifcctl(trap.IFC_OUTPUT, 0, trap.CTL_BUFFERSWITCH, 0) # Disable output buffering

def print_commands():
   print "Commands: [P]rint record, [E]dit record, [S]end record, [H]elp, E[x]it"

def print_help():
   print """\
Available commands:
  'print' 'p'  Print current contents of the record.
  'edit'  'e'  Edit values of all fields of the record.
  'send'  's'  Send the record to the output interface.
               To send multiple records, put an integer number after the
               command, e.g. 's 5' to send 5 records.
  'help'  'h'  Print this help.
  'exit'  'x'  Exit the Debug Sender
  'quit'  'q'  Exit the Debug Sender
"""

def print_record():
   global record, record_metadata
   for name,value in record:
      print "%s = %s%s" % (name, value if not isinstance(value, str) else '"'+value+'"', " {"+record_metadata[name]+"}" if name in record_metadata else "")


def edit_record():
   global record, record_metadata
   for name in record.fields():
      val = getattr(record, name)
      while True:
         valstr = raw_input("%s [%s]%s: " % (name, val if not isinstance(val, str) else '"'+val+'"', " {"+record_metadata[name]+"}" if name in record_metadata else ""))
         if valstr == "":
            break # Continue with next field

         field_type = record._field_types[name]

         # Try special cases first, then all other cases
         if not edit_time_rules(name, valstr):
            try:
               if hasattr(field_type, "fromString"):
                  val = field_type.fromString(valstr)
               else:
                  val = field_type(valstr)
            except Exception, e:
               print "Unable to convert %r to %s:" % (valstr, field_type.__name__),
               print e
               continue # Try it again
            setattr(record, name, val)

         break # Continue with next field
   print


def send_record(count=1):
   global record
   if count == 1:
      print "Sending the record ...",
   else:
      print "Sending %i records ..." % count,
   sys.stdout.flush()
   try:
      for _ in range(count):
         send_time_rules() # Edit record according to send-time rules
         trap.send(0, record.serialize())
      print "done"
   except trap.ETerminated:
      print
      trap_terminated()
      return
   except Exception, e:
      print
      print "ERROR:", e


def trap_terminated():
   print "** TRAP interface was terminated (probably by pressing Ctrl-C). **"
   print "You can [R]einitialize TRAP or E[x]it"
   while True:
      cmd = raw_input("> ")
      cmd = cmd.strip().lower()
      if cmd == "":
         continue
      elif cmd == "r":
         # Reinitialize TRAP
         try:
            trap.finalize()
         except trap.ENotInitialized:
            pass
         try:
            init_trap()
         except trap.TRAPException, e:
            print e
            continue
         print "TRAP reinitialized."
         print_commands()
         return
      elif cmd == "x" or cmd == "exit" or cmd == "q" or cmd == "quit":
         exit(0)
      else:
         print "Unknown command. Enter 'r' or 'x'."


def edit_time_rules(name, valstr):
   global record, record_metadata
   wrapper = {'is_special': False, 'val': getattr(record, name)}

   # Validity check
   if not match(r"!?([+-].+)?$", valstr) and not (isinstance(wrapper['val'], Timestamp) and match(r"!?(now)?([+-].+)?$", valstr)):
      return wrapper['is_special'] # Is not special or is invalid

   # Gather send-time rules, don't apply
   if valstr.startswith('!'):
      wrapper['is_special'] = True
      if valstr == '!': # Delete
         if name in record_metadata:
            del record_metadata[name]
      else: # Add or update
         record_metadata[name] = valstr
      return wrapper['is_special'] # True

   # Apply edit-time rules
   try:
      apply_rules(wrapper, valstr)
   except Exception, e:
      print e
      return wrapper['is_special'] # Should be false

   setattr(record, name, wrapper['val']) # Save attribute to record
   return wrapper['is_special'] # False also in case of parsing error

def send_time_rules():
   global record, record_metadata

   for name in record_metadata:
      wrapper = {'is_special': False, 'val': getattr(record, name)}
      valstr = record_metadata[name][1:] # Croup out "!"
      apply_rules(wrapper, valstr) # Apply send-time rules
      setattr(record, name, wrapper['val'])

def apply_rules(wrapper, valstr):
   val = wrapper['val']
   is_special = wrapper['is_special']

   if isinstance(val, Timestamp): # Timestamp is treated specially
      if valstr.startswith("now"):
         val = Timestamp.now()
         valstr = valstr[len("now"):] # Crop out "now"
         is_special = True

      if valstr.startswith(('+', '-')):
         val += int(valstr)
         is_special = True
   elif valstr.startswith('+'):
      valstr = valstr[len('+'):] # Crop out "+"
      try: # First try by converting inserted string to attribute type
         val += type(val)(valstr)
         is_special = True
      except: # Second try by converting inserted string to integer
         val += int(valstr)
         is_special = True
   elif valstr.startswith('-'):
      valstr = valstr[len('-'):] # Crop out "-"
      try: # First try by converting inserted string to attribute type
         val -= type(val)(valstr)
         is_special = True
      except: # Second try by converting inserted string to integer
         val -= int(valstr)
         is_special = True

   wrapper['val'] = val
   wrapper['is_special'] = is_special

# --------------------------------------------------------------------

# Parse TRAP params
ifc_spec = trap.parseParams(sys.argv, module_info)


if len(sys.argv) != 2:
   print "Usage:\n      python debug_sender.py -i IFC_SPEC UNIREC_FORMAT"
   exit(1)

# Create UniRec template
URTmplt = unirec.CreateTemplate("URTmplt", sys.argv[1])
record = URTmplt()
record_metadata = dict() # To save send-time rules

# TODO zaridit, aby si UniRec pamatoval poradi polozek tak, jak je mu predano
#  razeni podle velikosti a abecedy by mela byt jen interni zalezitost
#  (UniRec objekt si bude pamatovat dva seznamy polozek)


# Inititalize module
init_trap()
trap.set_data_fmt(0, trap.TRAP_FMT_UNIREC, sys.argv[1])

# Main loop
print "Current record:"
print_record()
print
print_commands()

while True:
   cmd = raw_input("> ")
   cmd, _, param = cmd.partition(' ')
   cmd = cmd.strip().lower()
   param = param.strip()
   if cmd == "":
      continue
   elif cmd == "s" or cmd == "send":
      cnt = 1
      if param:
         try:
            cnt = int(param)
         except ValueError:
            print "ERROR: Parameter of 'send' command must be an integer."
            continue
      send_record(cnt)
   elif cmd == "e" or cmd == "edit":
      edit_record()
   elif cmd == "p" or cmd == "print":
      print_record()
   elif cmd == "h" or cmd == "help":
      print_help()
   elif cmd == "x" or cmd == "exit" or cmd == "q" or cmd == "quit":
      exit(0)
   else:
      print "Unknown command"

