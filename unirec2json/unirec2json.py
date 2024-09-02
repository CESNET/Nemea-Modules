#!/usr/bin/python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import pytrap
import sys
import optparse
import json
import re
from optparse import OptionParser

parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
        help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option("-n", "--no-eos", action="store_true",
        help="Don't send end-of-stream message at the end.")
parser.add_option("-M", "--maps", dest="maps", metavar="JSONFILE",
        help="Load mappings and apply them on incoming messages.")
parser.add_option("-v", "--verbose", action="store_true",
        help="Set verbose mode - print messages.")
parser.add_option("-f", "--format", dest="format", default="",
    help="Set format identifier string (this must match the format ID required by receiving module)", metavar="FMT_ID")

# Parse remaining command-line arguments
(options, args) = parser.parse_args()

trap = pytrap.TrapCtx()
trap.init(sys.argv, 1, 1)

trap.setRequiredFmt(0, pytrap.FMT_UNIREC)

# Set format of data on the output interface
trap.setDataFmt(0, pytrap.FMT_JSON, options.format)

def default(o):
    if isinstance(o, pytrap.UnirecIPAddr):
        return str(o)
    elif isinstance(o, pytrap.UnirecTime):
        return float(o)
    else:
        return repr(o)

mapping = None

if options.maps:
    with open(options.maps, "r") as f:
        mapping = json.load(f)

def apply_mappings(data, mapping):
    matches = mapping.get("match", None)
    regexs = mapping.get("regex", None)
    timify = mapping.get("timify", None)
    if matches:
        for field in matches:
            data[field["dest"]] = field["mapping"].get(str(data[field["src"]]), None)

    if regexs:
        for field in regexs:
            for reg in field["mapping"].keys():
                if re.match(reg, str(data[field["src"]])):
                    data[field["dest"]] = field["mapping"][reg]
    if timify:
        for t in timify:
            data[t] = pytrap.UnirecTime(float(data[t])).format()
    return data

# Main loop
stop = False
while not stop:
    try:
        data = trap.recv()
    except pytrap.FormatChanged as e:
        fmttype, inputspec = trap.getDataFmt(0)
        rec = pytrap.UnirecTemplate(inputspec)
        data = e.data
    if len(data) <= 1:
        # Send end-of-stream message and exit
        if not options.no_eos:
            trap.send(bytearray(b"0"))
            trap.sendFlush(0)
        break
    rec.setData(data)
    d = rec.getDict()
    if mapping:
        d = apply_mappings(d, mapping)
    j = json.dumps(d, default=default)
    if options.verbose:
        print(j)
    trap.send(bytearray(j, "utf-8"))

# Free allocated TRAP IFCs
trap.finalize()

