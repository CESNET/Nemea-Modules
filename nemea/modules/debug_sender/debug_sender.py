#!/usr/bin/python

import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "python"))
import trap
import unirec
import readline

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
   global record
   for name,value in record:
      print "%s = %s" % (name, value if not isinstance(value, str) else '"'+value+'"')


def edit_record():
   global record
   for name in record.fields():
      val = getattr(record, name)
      while True:
         valstr = raw_input("%s [%s]: " % (name, val if not isinstance(val, str) else '"'+val+'"'))
         if valstr == "":
            break # Continue with next field
         
         field_type = record._field_types[name]
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
         trap.sendData(0, record.serialize(), trap.WAIT)
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


# --------------------------------------------------------------------

# Parse TRAP params
ifc_spec = trap.parseParams(sys.argv, module_info)


if len(sys.argv) != 2:
   print "Usage:\n      python debug_sender.py -i IFC_SPEC UNIREC_FORMAT"
   exit(1)

# Create UniRec template
URTmplt = unirec.CreateTemplate("URTmplt", sys.argv[1])
record = URTmplt()

# TODO zaridit, aby si UniRec pamatoval poradi polozek tak, jak je mu predano
#  razeni podle velikosti a abecedy by mela byt jen interni zalezitost
#  (UniRec objekt si bude pamatovat dva seznamy polozek)


# Inititalize module
init_trap()

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

