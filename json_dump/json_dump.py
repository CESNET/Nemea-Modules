#!/usr/bin/python3

import sys
import os.path
import socket
import io
import pytrap
import json
import optparse

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
      help="See https://nemea.liberouter.org/trap-ifcspec/", metavar="IFCSPEC")
parser.add_option("-w", dest="filename",
    help="Write dump to FILE instead of stdout (overwrite file)", metavar="FILE")
parser.add_option("-a", dest="filename_append",
    help="Write dump to FILE instead of stdout (append to file)", metavar="FILE")
parser.add_option("-s", dest="networktarget",
    help="Stream data over TCP", metavar="HOST:PORT")
parser.add_option("-I", "--indent", metavar="N", type=int,
    help="Pretty-print JSON with indentation set to N spaces. Note that such format can't be read by json_replay module.")
parser.add_option("-v", "--verbose", action="store_true",
    help="Set verbose mode - print messages.")
parser.add_option("--noflush", action="store_true",
    help="Disable automatic flush of output buffer after writing a record (may improve performance).")


# Parse remaining command-line arguments
(options, args) = parser.parse_args()

# Initialize module
trap = pytrap.TrapCtx()
trap.init(["-i", options.ifcspec])

# Open output file
if (options.filename and options.filename_append or
    options.filename and options.networktarget or
    options.filename_append and options.networktarget):
    sys.stderr.write("Error: -w, -a, -s are mutually exclusive.")
    sys.exit(1)
if options.filename:
    file = open(options.filename, "w", encoding="utf-8")
elif options.filename_append:
    file = open(options.filename_append, "a", encoding="utf-8")
elif options.networktarget:
    try:
        addr, port = options.networktarget.split(":")
        port = int(port)
    except (TypeError, ValueError):
        sys.stderr.write("Error: malformed argument of -s host:port")
        sys.exit(1)
    s = socket.create_connection((addr, port))
    file = s.makefile("w", encoding="utf-8")
else:
    file = sys.stdout

# Set JSON as required data type on input
trap.setRequiredFmt(0, pytrap.FMT_JSON, "")

stop = False
# Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
while not stop:
    # Read data from input interface
    try:
        data = trap.recv()
    except pytrap.FormatMismatch:
        sys.stderr.write("Error: output and input interfaces data type or format mismatch\n")
        break
    except pytrap.FormatChanged as e:
        if options.verbose:
            print(trap.getDataFmt(0))
        data = e.data
        del(e)
        pass
    except (pytrap.Terminated, KeyboardInterrupt):
        break

    # Check for "end-of-stream" record
    if len(data) <= 1:
        if options.verbose:
            print('Received "end-of-stream" message, going to quit.')
        break

    try:
        # Decode data (and check it's valid JSON)
        rec = json.loads(data.decode("utf-8"))
        if options.verbose:
            print("Message: {0}".format(rec))
        # Print it to file, stdout, or send to socket
        file.write(json.dumps(rec, indent=options.indent) + '\n')
        if not options.noflush:
            file.flush()
    except ValueError as e:
        sys.stderr.write(str(e) + '\n')

