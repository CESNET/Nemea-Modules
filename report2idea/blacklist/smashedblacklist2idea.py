#!/usr/bin/python3

"""
smashedblacklist2idea.py is a reporter module for blacklistfilter to convert
aggregated output to IDEA alert format.

The expected input:
    {"ts_first": 1564389842.799, "protocol": 6, "source_ports": [443],
        "source_ip": "158.194.161.97", "tgt_sent_packets": 20, "is_only_fqdn":
            true, "source_url": "moravianjournal.upol.cz", "tgt_sent_flows": 2,
        "referer": "", "type": "url", "blacklist_id": 1, "ts_last":
            1564389844.246, "agg_win_minutes": 5, "tgt_sent_bytes": 1978,
        "targets": ["18.191.86.84"]}

The example output:
    TODO!
"""

import argparse
from datetime import timedelta
import sys
import traceback
import json
import pytrap


# The whole functionality of reporting is here:
from report2idea import getIDEAtime, getRandomId, Run, setAddr


# Moudle name, description and required input data format
MODULE_NAME = "smashedblacklist"
MODULE_DESC = "Converts output of blacklistfilter module with sMaSheD blacklist to IDEA alert format."

REQ_TYPE = pytrap.FMT_JSON
REQ_FORMAT = "aggregated_blacklist"

PROTO_CONV = {
    6: 'tcp',
    17: 'udp',
}

GUARDED_PREFIXES = None

def load_prefixes(filepath):
    """
    Load JSON file from `filepath` and convert the data into the list of IP ranges.

    Args:
        filepath: path to the configuration file with prefixes

    Returns:
        list: UnirecIPAddrRange
    """
    prefixes = None

    try:
        with open(filepath, "r") as f:
            j = json.load(f)
        prefixes = [pytrap.UnirecIPAddrRange(pref["ip_prefix"]) for pref in j]
    except Exception as e:
        print("ERROR: Can't load prefixes from file '{0}': {1}.".format(filepath, traceback.print_exc()), file=sys.stderr)

    return prefixes

def convert_to_idea(rec, opts=None):
    """
    Converts the aggregated ipblacklistfilter event(json) to the IDEA format.
    This module represents only one type of events - Cryptocurrency mining -
    for the sake of simplicity.
    For more universal purpose, use blacklist2idea.py.

    Args:
        rec: the record from ipblacklistfilter and aggregator
        opts: cmd options

    Returns:
        dict: idea
    """
    global GUARDED_PREFIXES

    if not GUARDED_PREFIXES:
        GUARDED_PREFIXES = load_prefixes(opts.prefixes)

    idea = {
        "Category": ["Suspicious.Miner"],
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(),
        "EventTime": getIDEAtime(pytrap.UnirecTime(rec["ts_first"])),
        "DetectTime": getIDEAtime(pytrap.UnirecTime(rec["ts_last"])),
        "CeaseTime": getIDEAtime(pytrap.UnirecTime(rec["ts_last"])),
        "Description": "Possible CryptoCurrency mining identified by connection with a mining pool.",
        "Source": [],
        "Target": [],
        "Node": [{
            "Name": "undefined",
            "SW": ["Nemea", "blacklistfilter"],
            "AggrWin": minutes_to_aggr_win(int(rec["agg_win_minutes"])),
            "Type": ["Flow", "Blacklist"]
        }],
        "Ref": ["http://smashed.fit.vutbr.cz:8080/miningProp/json"]
    }

    if rec["protocol"] in PROTO_CONV:
        proto = PROTO_CONV[rec["protocol"]]
        idea['Source'].append({'Proto': [proto]})
        idea['Target'].append({'Proto': [proto]})

    miners = [pytrap.UnirecIPAddr(t) for t in rec["targets"]]
    pool = pytrap.UnirecIPAddr(rec["source"])
    idea['Source'][0]["Type"] = "Miner"

    for miner in miners:
        setAddr(idea['Source'][0], miner)

    # look up pool IP in guarded prefixes
    if GUARDED_PREFIXES and any([pool in p for p in GUARDED_PREFIXES]):
        # own guarded resource was detected as a pool - add as Source
        idea['Source'].append({"Proto": [proto]})
        setAddr(idea['Source'][1], pool)
        idea['Source'][1]["Type"] = "MiningPool"
        idea['Note'] = 'IP {1} and port(s) {2} is listed as a mining pool server (by sMaSheD list of cryptocurrency mining pools), and IP {0} communicated with this service - possible miner.'.format(", ".join([str(m) for m in miners]), str(pool), ", ".join([str(p) for p in rec["source_ports"]]))
        del idea['Target']
    else:
        # pool is just an external IP and our resource is a potential miner
        # - add pool as Target
        setAddr(idea['Target'][0], pool)
        idea['Target'][0]["Type"] = "MiningPool"
        idea['Note'] = 'Detected possible CryptoCurrency mining by IP {0}, because of observed communication with {1}:{2} listed as a mining pool server (by sMaSheD list of cryptocurrency mining pools).'.format(", ".join([str(m) for m in miners]), str(pool), ", ".join([str(p) for p in rec["source_ports"]]))

    return idea


def minutes_to_aggr_win(minutes):
    """
    Converts minutes to IDEA AggrWin format (e.g. 00:05:00 or 536D10:20:30)

    Args:
        minutes (int): minutes to convert

    Returns:
        str: converted string
    """

    td = str(timedelta(minutes=minutes))
    if minutes < 600:
        return "0" + td
    if minutes < 1440:
        return td

    days, time = td.split(',')
    if minutes % 1440 < 600:
        time = "0" + time.strip()

    return days.split(' ')[0] + "D" + time.strip()


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
PARSER = argparse.ArgumentParser()
PARSER.add_argument('--blacklist-config', help="Set path to config file of blacklist downloader. Default: /etc/nemea/blacklistfilter/bl_downloader_config.xml",
                    default="/etc/nemea/blacklistfilter/bl_downloader_config.xml")
PARSER.add_argument("--prefixes", type=str, metavar="FILE", help="""
    JSON file with guarded IP prefixes, it must be an array of objects with "ip_prefix" key,
    e.g., [{... "ip_prefix":"10.0.10.0/24" ...}].
    When a pool server is found in one of the prefixes, it is reported as Source,
    otherwise (or when no prefixes are specified) it is reported as Target.""")

# Run the module
if __name__ == "__main__":
    Run(
        module_name=MODULE_NAME,
        module_desc=MODULE_DESC,
        req_type=REQ_TYPE,
        req_format=REQ_FORMAT,
        conv_func=convert_to_idea,
        arg_parser=PARSER
    )
