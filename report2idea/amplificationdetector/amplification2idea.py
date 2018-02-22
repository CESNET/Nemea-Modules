#!/usr/bin/env python

from __future__ import absolute_import

# In case we are in nemea/modules/report2idea/amplificationdetector and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "amplification2idea"
MODULE_DESC = "Converts output of amplification_detection module to IDEA."
REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,uint64 REQ_BYTES,uint64 RSP_BYTES,time TIME_FIRST,time TIME_LAST,uint32 EVENT_ID,uint32 REQ_FLOWS,uint32 REQ_PACKETS,uint32 RSP_FLOWS,uint32 RSP_PACKETS,uint16 SRC_PORT"

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict)
    """
    endTime = getIDEAtime(rec.TIME_LAST)
    idea={
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "CeaseTime": endTime,
        "DetectTime": endTime,
        "Type": [ "Flow", "Statistical" ],
        "Category": [ "Availability.DDoS" ],
        "Source": [{
            'Type': ['Backscatter'],
            'InFlowCount': rec.REQ_FLOWS,
            'InPacketCount': rec.REQ_PACKETS,
            'InByteCount': rec.REQ_BYTES,
            'OutFlowCount': rec.RSP_FLOWS,
            'OutPacketCount': rec.RSP_PACKETS,
            'OutByteCount': rec.RSP_BYTES,
        }],
        "Target": [{
            'InFlowCount': rec.RSP_FLOWS,
            'InPacketCount': rec.RSP_PACKETS,
            'InByteCount': rec.RSP_BYTES,
        }],
        "FlowCount": int(rec.RSP_FLOWS),
        "ByteCount": int(rec.RSP_BYTES),
        "PacketCount": int(rec.RSP_PACKETS),

        'Node': [{
            'Name': 'undefined',
            'SW': ['Nemea', 'amplification_detection' ],
        }],
    }
    setAddr(idea['Source'][0], rec.SRC_IP)
    setAddr(idea['Target'][0], rec.DST_IP)
    if rec.SRC_PORT == 53:
        idea['Description'] = 'DNS amplification'
        idea['Source'][0]['Proto'] = ['udp', 'dns']
        idea['Target'][0]['Proto'] = ['udp', 'dns']
    elif rec.SRC_PORT == 123:
        idea['Description'] = 'NTP amplification'
        idea['Source'][0]['Proto'] = ['udp', 'ntp']
        idea['Target'][0]['Proto'] = ['udp', 'ntp']

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

