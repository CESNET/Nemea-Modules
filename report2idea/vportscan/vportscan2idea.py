#!/usr/bin/env python

from __future__ import absolute_import

# In case we are in nemea/modules/report2idea/vportscan and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

from report2idea import *

# Moudle name, description and required input data format
MODULE_NAME = "vportscan2idea"
MODULE_DESC = "Converts output of vportscan detector (vertical scans) to IDEA."
REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,uint32 PORT_CNT,time TIME_FIRST,time TIME_LAST,uint16 DST_PORT,uint16 SRC_PORT,uint8 EVENT_TYPE,uint8 PROTOCOL"

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
       "FlowCount": int(rec.PORT_CNT),
       "Description": "Vertical scan using TCP SYN",
       "Source": [{
             "Proto": ["tcp"]
        }],
       "Target": [{
             "Proto": ["tcp"],
       }],
       'Node': [{
          'Name': 'undefined',
          'SW': ['Nemea','vportscan_detector'],
          'Type': ['Flow', 'Statistical'],
          'AggrWin': '00:10:00',
       }],
    }
    # Set IP addresses (IPv4 / IPv6)
    setAddr(idea['Source'][0], rec.SRC_IP)
    setAddr(idea['Target'][0], rec.DST_IP)
    return idea


# Run the module
if __name__ == "__main__":
   Run(MODULE_NAME, MODULE_DESC, REQ_TYPE, REQ_FORMAT, convert_to_idea)

