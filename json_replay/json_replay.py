#!/usr/bin/python3

import sys
import pytrap
import json

import argparse

parser = argparse.ArgumentParser(
    description='Load JSON data from a file (or stdin) and send it to the output interface. '
                'There should be one JSON record per line in the file. '
                'If multiple files are passed, they are read in sequence.')
parser.add_argument('input_files', metavar='FILE', nargs='*', type=argparse.FileType('r', encoding='utf-8'),
    help='One or more input files to process. If none is specified, reads from stdin.')
parser.add_argument('-i', '--ifcspec', dest='ifcspec',
    help='See https://nemea.liberouter.org/trap-ifcspec/', metavar='IFCSPEC')
parser.add_argument('-f', '--format', dest='format', default='',
    help='Set format identifier string (this must match the format ID required by receiving module)', metavar='FMT_ID')
parser.add_argument('-n', '--no-eos', action='store_true',
    help="Don't send end-of-stream message at the end.")
parser.add_argument('-v', '--verbose', action='store_true',
    help='Set verbose mode - print messages.')

# Parse remaining command-line arguments
args = parser.parse_args()

# Initialize module
trap = pytrap.TrapCtx()
trap.init(sys.argv, 0, 1)

# Set format of data on the output interface
trap.setDataFmt(0, pytrap.FMT_JSON, args.format)

# Set timeout of output interface to "WAIT"
trap.ifcctl(0, False, pytrap.CTL_TIMEOUT, pytrap.TIMEOUT_WAIT)

# Main loop
file_index = 0
line_index = 0
while True:
    # Read one record from input file
    line = args.input_files[file_index].readline()
    if not line: # EOF
        if file_index + 1 < len(args.input_files):
            # read next file
            args.input_files[file_index].close()
            file_index += 1
            line_index = 0
            continue
        else:
            # no more files
            # Send end-of-stream message and exit
            if not args.no_eos:
                trap.send(bytearray(b"0"))
            trap.sendFlush(0)
            break

    line_index += 1
    if line == "\n":
        continue

    # Parse JSON
    try:
        rec = json.loads(line)
    except ValueError:
        print(f"Error: Can't decode JSON record in '{args.input_files[file_index].name}' line {line_index}. The line is skipped.", file=sys.stderr)
        continue

    if args.verbose:
        print(json.dumps(rec))

    # Send JSON to output ifc
    trap.send(bytearray(json.dumps(rec), "utf-8"))

