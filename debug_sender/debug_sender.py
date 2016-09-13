#!/usr/bin/python
#
# Copyright (C) 2013-2016 CESNET
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
import readline
from re import match
import argparse
import cmd
import pytrap

trap = pytrap.TrapCtx()

fieldOrder = []

# ----------------------------------------------------------------------------

def init_trap():
   trap.init(sys.argv, 0, 1)
   trap.ifcctl(0, False, pytrap.CTL_BUFFERSWITCH, 0) # Disable output buffering


class Commands(cmd.Cmd):
   prompt = '> '
   doc_leader = """This shows the list of commands.
If you want to see help to a specific command, type help and 'command' (e.g. help print).
Character in apostrophs is an abbreviation of the command (e.g. p for print).
"""
   doc_header = 'Available commands:'
   ruler = '-'
   intro = """Type help to get list of commands."""

   # Commands are methods with name starting with "do_"
   # Help string of a command is a docstring of the command method.
   # The first 3 characters of docstring must be apostroph, character, apostroph
   # The character is an abbreviation of a command.

   def do_print(self, line = ""):
      """'p'  Print current contents of the record."""
      global urtmplt, record, record_metadata, fieldOrder
      t = "Current record:\n"
      for name in fieldOrder:
         value = urtmplt.get(record, name)
         t = t + "%s = %s%s\n" % (name, value if not isinstance(value, str) else '"'+value+'"', " {"+record_metadata[name]+"}" if name in record_metadata else "")
      print(t)

   def do_edit(self, line):
      """'e'  Edit values of all fields of the record."""
      global urtmplt, record, record_metadata, fieldOrder
      for name in fieldOrder:
         val = urtmplt.get(record, name)
         while True:
            valstr = raw_input("%s [%s]%s: " % (name, val if not isinstance(val, str) else '"'+val+'"', " {"+record_metadata[name]+"}" if name in record_metadata else ""))
            if valstr == "":
               break # Continue with next field

            field_type = urtmplt.getFieldType(name)

            # Try special cases first, then all other cases
            if not edit_time_rules(name, valstr):
               try:
                  val = field_type(valstr)
               except Exception, e:
                  print "Unable to convert %r to %s:" % (valstr, field_type.__name__),
                  print e
                  continue # Try it again
               urtmplt.set(record, name, val)

            break # Continue with next field
      print

   def do_stop(self, line):
      """'t'  Send terminate message."""
      try:
         trap.send(bytes("0"), 0)
         print "done"
      except pytrap.Terminated:
         print("Libtrap was terminated")
         return True
      except Exception, e:
         print "\nERROR:", e

   def do_send(self, line):
      """'s'  Send the record to the output interface.
                  To send multiple records, put an integer number after the
                  command, e.g. 's 5' to send 5 records."""
      global record
      count = 1
      if line:
         try:
            count = int(line)
         except ValueError:
            print "ERROR: Parameter of 'send' command must be an integer."
      if count == 1:
         print "Sending the record ...",
      else:
         print "Sending %i records ..." % count,
      sys.stdout.flush()
      try:
         for _ in range(int(count)):
            send_time_rules() # Edit record according to send-time rules
            # Record was allocated of maximum size, extract only bytes that contain record data
            data_to_send = record[:urtmplt.recSize(record)]
            trap.send(data_to_send, 0)
         print "done"
      except pytrap.Terminated:
         print("Libtrap was terminated")
         return True
      except Exception, e:
         print "\nERROR:", e

   def do_exit(self, line):
      """'x'  Exit the Debug Sender"""
      return True

   def do_quit(self, line):
      """'q'  Exit the Debug Sender"""
      return True

   def do_EOF(self, line):
      return True

   def __init__(self):
      cmd.Cmd.__init__(self)
      # add abbr_ attributes of the class, it is used to support "one-char synonym" for a command
      # docstring of command method is used
      names = self.get_names()
      a = filter(lambda x: x.startswith("abbr_"), names)
      for i in filter(lambda x: x.startswith("do_"), names):
         abbrname = "abbr_" + i[3:]
         if abbrname not in a:
            fcn = getattr(Commands, i)
            doc = getattr(fcn, "__doc__")
            setattr(Commands, "abbr_"+i[3:], doc.__str__()[1])

   def parseline(self, line):
      # try to find abbreviation of command
      words = line.split()
      if words and words[0]:
         for attr in self.get_names():
            if attr.startswith("abbr_") and getattr(self, attr) == words[0]:
               # found command, replace in line
               words[0] = attr[5:]
               line = " ".join(words)
               break

      # do the original Cmd parsing
      return cmd.Cmd.parseline(self, line)
# end of Commands class

def edit_time_rules(name, valstr):
   global urtmplt, record, record_metadata
   wrapper = {'is_special': False, 'val': urtmplt.get(record, name)}

   # Validity check
   if not match(r"!?([+-].+)?$", valstr) and not (isinstance(wrapper['val'], pytrap.UnirecTime) and match(r"!?(now)?([+-].+)?$", valstr)):
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

   urtmplt.set(record, name, wrapper['val']) # Save attribute to record
   return wrapper['is_special'] # False also in case of parsing error

def send_time_rules():
   global urtmplt, record, record_metadata

   for name in record_metadata:
      wrapper = {'is_special': False, 'val': getattr(record, name)}
      valstr = record_metadata[name][1:] # Croup out "!"
      apply_rules(wrapper, valstr) # Apply send-time rules
      urtmplt.set(record, name, wrapper['val'])

def apply_rules(wrapper, valstr):
   val = wrapper['val']
   is_special = wrapper['is_special']

   if isinstance(val, pytrap.UnirecTime): # UnirecTime is treated specially
      if valstr.startswith("now"):
         val = pytrap.UnirecTime.now()
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


MODULE_DESCR = """Debug Sender (NEMEA module)
Inputs: 0
Outputs: 1 (UniRec, format given as parameter)

This module allows to manually send arbitrary UniRec records to a TRAP
interface. You have to specify UniRec format at startup, everything other is
done interactively by writing simple commands.
"""

parser = argparse.ArgumentParser(description=MODULE_DESCR)
parser.add_argument('-i', metavar='IFC_SPEC',
                    help='TRAP interface specifier.')
parser.add_argument('template', metavar='UNIREC_FORMAT',
                    help='UniRec specifier of the records to send, e.g. "uint32 FOO,string BAR"')
# TODO add common help for IFC_SPEC, it should probably be some constant in pytrap
parser.formatter_class = argparse.RawTextHelpFormatter # TODO: neco co zachova explicitni odradkovani (klidne tam dam \n) ale jinak vyresi inteligentni zalamovani
args = parser.parse_args()

# Create UniRec template and record
urtmplt = pytrap.UnirecTemplate(args.template)
record = bytearray(65536) # allocate empty record of maximal possible size (i.e. 64kB by Unirec definition)
record_metadata = dict() # To save send-time rules


# UniRec specifier was parsed and template created successfuly,
# remember field order from the specifier, we expect ',' as a field delimiter
# and ' ' as type and name delimiter
fieldOrder = [ f.split(' ')[1] for f in args.template.split(',') ]

# Inititalize module
init_trap()
trap.setDataFmt(0, pytrap.FMT_UNIREC, args.template)

# Main loop
if __name__ == '__main__':
   c = Commands()
   print("""Interactive Debug Sender
This module can be used to create UniRec messages and send them via TRAP.

Empty line means repeating the previous command.
""")
   c.do_print()
   c.cmdloop()

