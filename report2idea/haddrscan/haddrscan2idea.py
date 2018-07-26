#!/usr/bin/env python

from __future__ import absolute_import

# In case we are in nemea/modules/report2idea/haddrscan and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

from report2idea import *

# Moudle name, description and required input data format
MODULE_NAME = "haddrscan2idea"
MODULE_DESC = "Converts output of haddrscan detector (horizontal scans) to IDEA."
REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr SRC_IP,uint32 ADDR_CNT,time TIME_FIRST,time TIME_LAST," + \
             "uint16 DST_PORT,uint8 EVENT_TYPE,uint8 PROTOCOL," + \
             "ipaddr DST_IP0,ipaddr DST_IP1,ipaddr DST_IP2,ipaddr DST_IP3," + \
             "ipaddr DST_IP4,ipaddr DST_IP5,ipaddr DST_IP6,ipaddr DST_IP7," + \
             "ipaddr DST_IP8,ipaddr DST_IP9,ipaddr DST_IP10,ipaddr DST_IP11," + \
             "ipaddr DST_IP12,ipaddr DST_IP13,ipaddr DST_IP14,ipaddr DST_IP15"

# Main conversion function
def convert_to_idea(rec, opts):
    endTime = getIDEAtime(rec.TIME_LAST)
    idea={
       "Format": "IDEA0",
       "ID": getRandomId(),
       'CreateTime': getIDEAtime(),
       "EventTime": getIDEAtime(rec.TIME_FIRST),
       'CeaseTime': endTime,
       "DetectTime": endTime,
       "Category": ["Recon.Scanning"],
       "FlowCount": int(rec.ADDR_CNT),
       "Description": "Horizontal scan using TCP SYN",
       "Source": [{
             "Proto": ["tcp"]
        }],
       "Target": [{
         "Proto": ["tcp"],
         "Port": [rec.DST_PORT],
         "Imprecise": True
       }], # Target addresses are added later
       'Node': [{
          'Name': 'undefined',
          'SW': ['Nemea','haddrscan_detector'],
          'Type': ['Flow', 'Statistical'],
          'AggrWin': opts.aggrwin,
       }],
    }
    # Set IP addresses (IPv4 / IPv6)
    setAddr(idea['Source'][0], rec.SRC_IP)
    # Set Tartget IP addresses
    for ip in range(16):
        dstip = getattr(rec, "DST_IP" + str(ip), None)
        if dstip:
            setAddr(idea["Target"][0], dstip)
    return idea


# Run the module
if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--aggrwin', metavar="HH:MM:SS", default="00:05:00", type=str,
            help='Aggregation window length (AggrWin field of IDEA), default="00:05:00"')

    Run(MODULE_NAME, MODULE_DESC, REQ_TYPE, REQ_FORMAT, convert_to_idea, arg_parser)

