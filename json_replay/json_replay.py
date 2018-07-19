#!/usr/bin/env python

import sys
import os.path
import pytrap
import json
import optparse

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
      help="See https://nemea.liberouter.org/trap-ifcspec/", metavar="IFCSPEC")
parser.add_option("-f", "--format", dest="format", default="",
    help="Set format identifier string (this must match the format ID required by receiving module)", metavar="FMT_ID")
parser.add_option("-n", "--no-eos", action="store_true",
    help="Don't send end-of-stream message at the end.")
parser.add_option("-v", "--verbose", action="store_true",
    help="Set verbose mode - print messages.")

# Parse remaining command-line arguments
(options, args) = parser.parse_args()

# Initialize module
trap = pytrap.TrapCtx()
trap.init(sys.argv, 0, 1)

if len(args) > 1:
    sys.stderr.write("Error: Only one input file can be specified.")
elif len(args) == 1:
    file = open(args[0], "r")
else:
    file = sys.stdin

# Set format of data on the output interface
trap.setDataFmt(0, pytrap.FMT_JSON, options.format)

# Set timeout of output interface to "WAIT"
trap.ifcctl(0, False, pytrap.CTL_TIMEOUT, pytrap.TIMEOUT_WAIT)

# Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
i = 0 # line index
stop = False
while not stop:
    # Read one record from input file
    line = sys.stdin.readline()
    i += 1
    if not line: # EOF
        # Send end-of-stream message and exit
        if not options.no_eos:
            trap.send(bytearray(b"0"))
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

    if options.verbose:
        print(json.dumps(rec))

    # Send JSON to output ifc
    trap.send(bytearray(json.dumps(rec), "utf-8"))

