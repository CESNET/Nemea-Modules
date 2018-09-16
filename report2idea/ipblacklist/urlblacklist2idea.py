#!/usr/bin/env python

import argparse

# The whole functionality of reporting is here:
from report2idea import *
from datetime import timedelta

# Moudle name, description and required input data format
MODULE_NAME = "urlblacklist2idea"
MODULE_DESC = "Converts output of urlblacklistfilter module to IDEA."

REQ_TYPE = pytrap.FMT_JSON
REQ_FORMAT = "aggregated_urlblacklist"

# Blacklist ID to name lookup table (it is loaded from file specified by --blacklist-config in __main__)
bl_conv = {}

proto_conv = {
    1 : 'icmp',
    6 : 'tcp',
    17 : 'udp',
}


def load_config(config):
    """Load `config` file of blacklist_downloader module (bl_downloader_config.xml).
    This file contains a list of blacklists, their names and URLs.

    load_config() returns dictionary, where the key is id (= 2**ID from file) and
    value is a dictionary of "name", "type" and "source".
    """
    import xml.etree.ElementTree as xml
    bls = {}
    with open(config, "r") as f:
        tree = xml.parse(f)
    rootElement = tree.find(".//array[@type='URL']")
    blacklists = list(rootElement)

    for struct in blacklists:
        elems = list(struct)
        bl_id = None
        bl_name = None
        bl_type = None
        bl_source = None
        for el in elems:
            attr = el.attrib["name"]
            if attr == "name":
                bl_name = el.text
            elif attr == "id":
                bl_id = 2 ** (int(el.text) - 1)
            elif attr == "type":
                bl_type = el.text
            elif attr == "source":
                bl_source = el.text
        if not bl_id or not bl_name or not bl_type or not bl_source:
            sys.stderr.write("Incomplete configuration. " + str((bl_id, bl_name, bl_type)))
            break
        bls[bl_id] = {"name": bl_name, "type": bl_type, "source": bl_source}
    return bls


# Convert minutes to IDEA AggrWin format, e.g. 00:05:00 or 536D10:20:30
def minutes_to_aggr_win(minutes):
    td = str(timedelta(minutes=minutes))
    if minutes < 600:
        return "0" + td
    if minutes < 1440:
        return td

    days, time = td.split(',')
    if minutes % 1440 < 600:
        time = "0" + time.strip()

    return days.split(' ')[0] + "D" + time.strip()


# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Expected format is FMT_JSON and urlblacklist specifier.
          The example input data are as follows:
                {
                  "source_url": "avatars.mds.yandex.net",
                  "source_ports": [
                    443
                  ],
                  "targets": [
                    "147.231.11.227",
                    "147.231.253.30"
                  ],
                  "tgt_sent_flows": 2,
                  "ts_first": 1536661056.436,
                  "tgt_sent_bytes": 2793,
                  "source_ip": "87.250.247.181",
                  "ts_last": 1536661116.883,
                  "protocol": 6,
                  "tgt_sent_packets": 25,
                  "blacklist_bmp": 8,
                  "referer": "",
                  "agg_win_minutes": 5,
                  "is_only_fqdn": true
                }

                {
                    "source_url": "adamfoparadio.fr/PayPal/myaccount/card.php"
                    "is_only_fqdn": false,
                    "protocol": 6,
                    "source_ports": [
                        80
                    ],
                    "tgt_sent_bytes": 365,
                    "agg_win_minutes": 5,
                    "tgt_sent_packets": 6,
                    "ts_last": 1537128274.763,
                    "referer": "",
                    "blacklist_bmp": 4,
                    "tgt_sent_flows": 1,
                    "source_ip": "162.213.255.66",
                    "ts_first": 1537128273.047,
                    "targets": [
                        "192.168.1.107"
                    ],
                }

    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """
    global bl_conv

    if not bl_conv:
        bl_conv = load_config(opts.blacklist_config)

    protocol = ""
    if rec["protocol"] in proto_conv:
        protocol = proto_conv[rec["protocol"]]
    time_first = getIDEAtime(pytrap.UnirecTime(rec["ts_first"]))
    time_last = getIDEAtime(pytrap.UnirecTime(rec["ts_last"]))
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": time_first,
        "DetectTime": time_last,
        'CeaseTime': time_last,

        "Source": [],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'urlblacklistfilter' ],
            'Type': [ 'Flow', 'Blacklist' ],
            'AggrWin': minutes_to_aggr_win(int(rec["agg_win_minutes"]))
        }],
    }

    category = set()

    src_addr = { "Proto": [ protocol ] }
    src_entries = set()
    src_type = set()
    tgt_addr = { "Proto": [ protocol ] }
    tgt_type = set()
    sources = set()

    for ip in rec.get("targets", []):
        setAddr(tgt_addr, pytrap.UnirecIPAddr(ip))

    if rec["protocol"] in [6, 17] and rec["source_ports"]:
        src_addr["Port"] = rec["source_ports"]

    if rec["is_only_fqdn"]:
        src_addr["Hostname"] = rec["source_url"]
    else:
        src_addr["URL"] = rec["source_url"]

    src_type.add("OriginBlacklist")

    blacklist_bmp = rec.get("blacklist_bmp", 0)

    for bit in bl_conv:
        if bit & blacklist_bmp:
            cur_bl = bl_conv[bit]
        else:
            # this bit is not a blacklist
            continue

        curbltype = cur_bl["type"].lower()
        if curbltype == "malware":
            category.add("Malware" )
        elif curbltype == "phishing":
            category.add("Fraud.Phishing")
        elif curbltype == "booters":
            category.add("Fraud")
            src_type.add("Booter")
        elif curbltype == "botnet":
            category.add("Intrusion.Botnet")
            src_type.add("Botnet")
            src_type.add("CC")
            tgt_type.add("Botnet")

        src_entries.add(cur_bl["name"])
        sources.add(cur_bl["source"])

    setAddr(src_addr, pytrap.UnirecIPAddr(rec.get('source_ip')))

    if not category:
        # No threshold reached
        return None

    idea["Category"] = list(category)

    idea["Note"] = "URL: '{0}' was found on blacklist(s): {1}.".format((rec["source_url"]), ", ".join(list(src_entries)))

    if rec.get("targets", []):
        desctgt = "{0}".format(", ".join(rec["targets"])) if len(rec["targets"]) <= 3 else \
            (", ".join(rec["targets"][:3]) + " and {} more".format(len(rec["targets"][3:])))

        idea['Description'] = "URL: '{0}' (listed: {1}) was requested by {2}." \
            .format(rec["source_url"], ', '.join(list(src_entries)), desctgt)

    if src_type:
        src_addr["Type"] = list(src_type)
    if tgt_type:
        tgt_addr["Type"] = list(tgt_type)
    if rec["tgt_sent_flows"]:
        src_addr["InFlowCount"] = rec["tgt_sent_flows"]
        src_addr["InByteCount"] = rec["tgt_sent_bytes"]
        src_addr["InPacketsCount"] = rec["tgt_sent_packets"]

    idea['Source'].append(src_addr)

    # Add targets to Source (of trouble), since we want to send the alert to it
    if rec.get("targets", []):
        idea['Source'].append(tgt_addr)

    if sources:
        idea['Ref'] = list(sources)

    return idea


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
parser = argparse.ArgumentParser()
parser.add_argument('--blacklist-config', help="Set path to bl_downloader_config.xml of urlblacklistfilter. Default: /usr/local/etc/blacklistfilter/bl_downloader_config.xml ", default="/usr/local/etc/blacklistfilter/bl_downloader_config.xml ")

# Run the module
if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = parser
    )

