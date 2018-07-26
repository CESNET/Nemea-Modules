#!/usr/bin/env python

from __future__ import absolute_import

# In case we are in nemea/modules/report2idea/vportscan and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse
from report2idea import *

# Moudle name, description and required input data format
MODULE_NAME = "vportscan2idea"
MODULE_DESC = "Converts output of vportscan detector (vertical scans) to IDEA."
REQ_TYPE = pytrap.FMT_JSON
# REQ_FORMAT must match the value set by vportscan_aggregator.py
REQ_FORMAT = "aggregated_portscan"

# Main conversion function
def convert_to_idea(rec, opts):
    """ Convert rec, which is a JSON object similar to the following examples:

    {"src_ip": "1.8.9.39", "dst_ips": {"88.5.17.23": 400, "69.7.18.27": 2100,
    "98.4.48.85": 400}, "ts_first": 1455131428.0, "protocol": 6, "ts_last":
    1455131910.327}

    {"src_ip": "98.4.48.82", "dst_ips": {"1.8.9.39": 1350}, "ts_first":
    1455131462.223, "protocol": 6, "ts_last": 1455132113.437}

    "dst_ips" is a dict of IP addresses and their portcounts (number of scanned ports)
    """

    endTime = getIDEAtime(pytrap.UnirecTime(rec["ts_last"]))
    idea={
       "Format": "IDEA0",
       "ID": getRandomId(),
       'CreateTime': getIDEAtime(),
       "EventTime": getIDEAtime(pytrap.UnirecTime(rec["ts_first"])),
       'CeaseTime': endTime,
       "DetectTime": endTime,
       "Category": ["Recon.Scanning"],
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
          'AggrWin': opts.aggrwin,
       }],
    }
    # Set IP addresses (IPv4 / IPv6) and portcount
    setAddr(idea['Source'][0], pytrap.UnirecIPAddr(rec["src_ip"]))
    portcount = 0
    for ip in rec["dst_ips"]:
        setAddr(idea["Target"][0], pytrap.UnirecIPAddr(ip))
        portcount += rec["dst_ips"][ip]
    idea["FlowCount"] = portcount
    if len(rec["dst_ips"]) > 1:
        idea["Description"] = "Block portscan using TCP SYN"
    return idea


# Run the module
if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--aggrwin', metavar="HH:MM:SS", default="00:05:00", type=str,
            help='Aggregation window length (AggrWin field of IDEA), default="00:05:00"')

    Run(MODULE_NAME, MODULE_DESC, REQ_TYPE, REQ_FORMAT, convert_to_idea, arg_parser)

