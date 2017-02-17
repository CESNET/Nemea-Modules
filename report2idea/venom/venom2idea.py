#!/usr/bin/env python
# vim: shiftwidth=4:tabstop=4:expandtab:softtabstop=4

import argparse
from report2idea import *

# Moudle name, description and required input data format
MODULE_NAME = "venom2idea"
MODULE_DESC = "Converts output of venom detector module to IDEA."

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
    protocol = ""
    if rec.PROTOCOL in proto_conv:
        protocol = proto_conv[rec.PROTOCOL]
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "DetectTime": endTime,
        'CeaseTime': endTime,
        "Category": [ "Intrusion.Botnet", "Malware.Rootkit" ],
        "Confidence": 0.9,
        "PacketCount": rec.PACKETS,
        "ByteCount": rec.BYTES,

        "Source": [],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'venom_detector' ],
            'Type': [ 'Packet', 'DPI' ]
        }],
    }

    if rec.DST_IP:
        addr = {
            "Proto": [ protocol ]
        }
        if rec.PROTOCOL != 1:
            addr["Port"] = [ rec.DST_PORT ]
        addr["Type"] = [ "Botnet", "CC" ]
        setAddr(addr, rec.DST_IP)
        idea['Source'].append(addr)

    if rec.SRC_IP:
        addr = {
            "Proto": [ protocol ]
        }
        if rec.PROTOCOL != 1:
            addr["Port"] = [ rec.SRC_PORT ]
        addr["Type"] = [ "Botnet" ]
        setAddr(addr, rec.SRC_IP)
        idea['Source'].append(addr)

    idea['Note'] = "Activation was attempted by a packet with magic string in payload. It is unknown if the rootkit is present on the target machine."
    idea['Description'] = "Attempt to activate VENOM rootkit on {0}.".format(rec.DST_IP)
    idea['Ref'] = 'https://wiki.egi.eu/wiki/Venom_Rootkit'
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
