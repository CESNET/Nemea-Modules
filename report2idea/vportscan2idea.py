#!/usr/bin/env python

from common import Run
from uuid import uuid4
from time import time, gmtime
import trap
import unirec
import argparse


# Moudle name, description and required input data format
MODULE_NAME = "vportscan2idea"
MODULE_DESC = "Converts output of vportscan detector (vertical scans) to IDEA."
REQ_TYPE = trap.TRAP_FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,double EVENT_SCALE,time TIME_FIRST,time TIME_LAST,uint16 DST_PORT,uint16 SRC_PORT,uint8 EVENT_TYPE,uint8 PROTOCOL"

def setaddr(idea_field, addr):
   if isinstance(addr, unirec.ur_ipaddr.IP6Addr):
      idea_field['IP6'] = [str(addr)]
   else:
      idea_field['IP4'] = [str(addr)]

def get_isotime():
    t = time()
    g = gmtime(t)
    iso = '%04d-%02d-%02dT%02d:%02d:%02dZ' % g[0:6]
    return iso

# Main conversion function
# rec - Record recevied on TRAP input interface (the report to convert). Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
# opts - options parsed from command line (as returned by argparse.ArgumentParser)
# Return report in IDEA format (as Python dict)
def convert_to_idea(rec, opts=None):
    idea={
   "Format": "IDEA0",
   "ID": str(uuid4()),
   'CreateTime': get_isotime(),
   "DetectTime": rec.TIME_LAST.toString('%Y-%m-%dT%H:%M:%SZ'),
   "EventTime": rec.TIME_FIRST.toString('%Y-%m-%dT%H:%M:%SZ'),
   'CeaseTime': rec.TIME_LAST.toString('%Y-%m-%dT%H:%M:%SZ'),
   "Category": ["Recon.Scanning"],
   "ConnCount": long(rec.EVENT_SCALE),
   "Description": "Vertical scan using TCP SYN",
   "Source": [
      {
         "Proto": ["tcp"]
      }
   ],
   "Target": [
      {
         "Proto": ["tcp"],
      }
   ],
   'Node': [{
      'Name': 'undefined', # this will be filled by common part
         'SW': ['Nemea','vportscan_detector'],
      'Type': ['Flow', 'Statistical'],
      'AggrWin': '00:10:00',
   }],
}
    # Set IP addresses (IPv4 / IPv6)
    setaddr(idea['Source'][0], rec.SRC_IP)
    setaddr(idea['Target'][0], rec.DST_IP)
    return idea


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
#parser = argparse.ArgumentParser()

# Run the module
if __name__ == "__main__":
   Run(
       module_name = MODULE_NAME,
       module_desc = MODULE_DESC,
       req_type = REQ_TYPE,
       req_format = REQ_FORMAT,
       conv_func = convert_to_idea,
       arg_parser = None # (optional) Instance of argparse.ArgumentParser with some arguments defined can be passed - these arguments are then parsed from command line and passed to the conv_func)
   )
