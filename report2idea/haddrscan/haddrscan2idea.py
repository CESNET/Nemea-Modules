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
REQ_FORMAT = "ipaddr SRC_IP,uint32 ADDR_CNT,time TIME_FIRST,time TIME_LAST,uint16 DST_PORT,uint16 SRC_PORT,uint8 EVENT_TYPE,uint8 PROTOCOL"

# Main conversion function
def convert_to_idea(rec, opts=None):
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
             "Proto": ["tcp"],
             "Port": [rec.SRC_PORT]
        }],
       "Target": [{
             "Proto": ["tcp"],
             "Port": [rec.DST_PORT]
       }],
       'Node': [{
          'Name': 'undefined',
          'SW': ['Nemea','haddrscan_detector'],
          'Type': ['Flow', 'Statistical'],
          'AggrWin': '00:10:00',
       }],
    }
    # Set IP addresses (IPv4 / IPv6)
    setAddr(idea['Source'][0], rec.SRC_IP)
    return idea


# Run the module
if __name__ == "__main__":
   Run(MODULE_NAME, MODULE_DESC, REQ_TYPE, REQ_FORMAT, convert_to_idea)

