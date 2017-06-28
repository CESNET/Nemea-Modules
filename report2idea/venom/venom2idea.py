#!/usr/bin/env python
# vim: shiftwidth=4:tabstop=4:expandtab:softtabstop=4
from __future__ import absolute_import

# In case we are in nemea/modules/report2idea/venom and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse
from report2idea import *

# Moudle name, description and required input data format
MODULE_NAME = "venom2idea"
MODULE_DESC = """Creates IDEA messages for detected attempts of Venom rootkit activation.

Note: There is no Venom detection module in Nemea, the detection is done on exporter and a special field is added to flows detected as Venom activation attempt."""

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = 'ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL,uint8 VENOM'


proto_conv = {
    1 : 'icmp',
    6 : 'tcp',
    17 : 'udp',
}

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """

    endTime = getIDEAtime(rec.TIME_LAST)
    protocol = proto_conv.get(rec.PROTOCOL, "")
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "DetectTime": endTime,
        'CeaseTime': endTime,
        "Category": [ "Intrusion.Botnet", "Malware.Rootkit" ],
        "PacketCount": rec.PACKETS,
        "ByteCount": rec.BYTES,

        "Source": [],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'venom_detector' ],
            'Type': [ 'Packet', 'DPI' ]
        }],
    }

    if rec.SRC_IP:
        addr = {}
        if protocol:
            addr["Proto"] = [ protocol ]
        if rec.PROTOCOL == 6 or rec.PROTOCOL == 17: # TCP or UDP
            addr["Port"] = [ rec.SRC_PORT ]
        addr["Type"] = [ "Botnet", "CC" ]
        setAddr(addr, rec.SRC_IP)
        idea['Source'].append(addr)

    if rec.DST_IP:
        addr = {}
        if protocol:
            addr["Proto"] = [ protocol ]
        if rec.PROTOCOL == 6 or rec.PROTOCOL == 17: # TCP or UDP
            addr["Port"] = [ rec.DST_PORT ]
        addr["Type"] = [ "Botnet" ]
        setAddr(addr, rec.DST_IP)
        idea['Source'].append(addr)

    if rec.VENOM == 255:
        idea['Note'] = "Activation was attempted by a packet with magic string in payload. It is unknown if the rootkit is present on the target machine."
        idea['Confidence'] = 0.9
    else:
        idea['Note'] = "Activation was attempted by {0} packets with src_port + tcp_seq = 1221. It is unknown if the rootkit is present on the target machine.".format(rec.VENOM)
        idea['Confidence'] = 0.3

    # This is very often a false positive
    if rec.SRC_PORT == 1221:
        idea['Confidence'] = 0.05

    idea['Description'] = "Attempt to activate VENOM rootkit on {0}.".format(rec.DST_IP)
    idea['Ref'] = ['https://wiki.egi.eu/wiki/Venom_Rootkit']
    return idea

# Run the module
if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = None
    )
