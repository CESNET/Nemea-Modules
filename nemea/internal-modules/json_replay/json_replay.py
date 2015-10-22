#!/usr/bin/env python

import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "nemea-framework", "python"))
import trap
import json
import optparse # TODO change TRAP Python wrapper to use argparse

from optparse import OptionParser
parser = OptionParser(add_help_option=False)
parser.add_option("-f", "--format", dest="format", default="",
    help="Set format identifier string (this must match the format ID required by receiving module)", metavar="FMT_ID")
parser.add_option("-n", "--no-eos", action="store_true",
    help="Don't send end-of-stream message at the end.")


module_info = trap.CreateModuleInfo(
    "JSON replay", # Module name
    "Replay JSON data read from input file or stdin to TRAP interface. "
    "Each line of input must contain exactly one JSON record.",
    0, # Number of input interfaces
    1,  # Number of output interfaces
    parser
)


# Initialize module
ifc_spec = trap.parseParams(sys.argv, module_info)
trap.init(module_info, ifc_spec)
trap.registerDefaultSignalHandler()

# Parse remaining command-line arguments
(options, args) = parser.parse_args()

if len(args) > 1:
    sys.stderr.write("Error: Only one input file can be specified.")
elif len(args) == 1:
    file = open(args[0], "r")
else:
    file = sys.stdin

# Set format of data on the output interface
trap.set_data_fmt(0, trap.TRAP_FMT_JSON, options.format)

# Set timeout of output interface to "WAIT"
trap.ifcctl(trap.IFC_OUTPUT, 0, trap.CTL_SETTIMEOUT, trap.WAIT)

# Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
i = 0 # line index
while not trap.stop:
    # Read one record from input file
    line = sys.stdin.readline()
    i += 1
    if not line: # EOF
        # Send end-of-stream message and exit
        if not options.no_eos:
            trap.send(0, "0")
        trap.sendFlush(0)
        break
    if line == "\n":
        continue
    
    # Parse JSON
    try:
        rec = json.loads(line)
    except ValueError:
        sys.stderr.write("Error: Can't decode JSON record on line "+str(i)+". The line is skipped.\n")
        continue

    # Send JSON to output ifc
    #print "Sending", json.dumps(rec) # TODO verbose mode which would print what is being sent
    trap.send(0, json.dumps(rec))

