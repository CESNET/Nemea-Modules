#!/usr/bin/env python

import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "nemea-framework", "python"))
import trap
import json
import optparse # TODO change TRAP Python wrapper to use argparse

from optparse import OptionParser
parser = OptionParser(add_help_option=False)
parser.add_option("-w", dest="filename",
    help="Write dump to FILE instead of stdout (overwrite file)", metavar="FILE")
parser.add_option("-a", dest="filename_append",
    help="Write dump to FILE instead of stdout (append to file)", metavar="FILE")
parser.add_option("-I", "--indent", metavar="N", type=int,
    help="Pretty-print JSON with indentation set to N spaces. Note that such format can't be read by json_replay module.")

module_info = trap.CreateModuleInfo(
    "JSON dump", # Module name
    "Dump JSON data from input TRAP interface to file or standard output. Each JSON record is written to separate line.", # Description
    1, # Number of input interfaces
    0  # Number of output interfaces
)


# Initialize module
ifc_spec = trap.parseParams(sys.argv, module_info)
trap.init(module_info, ifc_spec)
trap.registerDefaultSignalHandler()

# Parse remaining command-line arguments
(options, args) = parser.parse_args()

# Open output file
if options.filename and options.filename_append:
    sys.stderr.write("Error: -w and -a are mutually exclusive.")
    sys.exit(1)
if options.filename:
    file = open(options.filename, "w")
elif options.filename_append:
    file = open(options.filename_append, "a")
else:
    file = sys.stdout

# Set JSON as required data type on input
trap.set_required_fmt(0, trap.TRAP_FMT_JSON, None)

# Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
while not trap.stop:
    # Read data from input interface
    try:
        data = trap.recv(0)
    except trap.EFMTMismatch:
        sys.stderr.write("Error: output and input interfaces data type or format mismatch\n")
        break
    except trap.EFMTChanged as e:
        # TODO: if verbose print message about new format
        data = e.data
        pass
    except trap.ETerminated:
        break

    # Check for "end-of-stream" record
    if len(data) <= 1:
        break

    # Decode data (and check it's valid JSON)
    rec = json.loads(data)
    # TODO catch exception if it's not valid JSON - print error message to stderr and continue

    # neprehazi se poradi polozek? mozna by bylo lepsi vypisovat primo "data" (pokud neni zapnuto indent)

    # Print it to file or stdout
    file.write(json.dumps(rec, indent=options.indent) + '\n')

