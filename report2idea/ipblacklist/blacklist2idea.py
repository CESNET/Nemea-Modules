#!/usr/bin/env python

import argparse

# The whole functionality of reporting is here:
from report2idea import *
from datetime import timedelta
import xml.etree.ElementTree as xml


# Moudle name, description and required input data format
MODULE_NAME = "blacklist2idea"
MODULE_DESC = "Converts output of (ip,url,dns)blacklistfilter modules to IDEA."

REQ_TYPE = pytrap.FMT_JSON
REQ_FORMAT = "aggregated_blacklist"

proto_conv = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
}

bl_config = None

# ---------------------------------------------------------------------------------------
# ------------------ DEFINITIONS OF IDEA CATEGORIES AS CLASSES --------------------------
# ---------------------------------------------------------------------------------------


class Common(object):
    def __init__(self, rec):
        self.idea = {
            "Category": rec["category"],
            "Format": "IDEA0",
            "ID": getRandomId(),
            "CreateTime": getIDEAtime(),
            "EventTime": getIDEAtime(pytrap.UnirecTime(rec["ts_first"])),
            "DetectTime": getIDEAtime(pytrap.UnirecTime(rec["ts_last"])),
            'CeaseTime': getIDEAtime(pytrap.UnirecTime(rec["ts_last"])),
            # TODO: Are these cumulative counts needed?
            "FlowCount": rec["src_sent_flows"] + rec["tgt_sent_flows"],
            "PacketCount": rec["src_sent_packets"] + rec["tgt_sent_packets"],
            "ByteCount": rec["src_sent_bytes"] + rec["tgt_sent_bytes"],
            'Node': [{
                'Name': 'undefined',
                'SW': ['Nemea', 'blacklistfilter'],
                'AggrWin': minutes_to_aggr_win(int(rec["agg_win_minutes"])),
                'Type': ['Flow', 'Blacklist']
            }],
        }

    def get_idea(self):
        return self.idea



class Malware(Common):
    def __init__(self, rec):
        super(Malware, self).__init__(rec)
        self.idea["co_jsem"] = 'Malware'


class SuspiciousBooter(Common):
    def __init__(self, rec):
        super(SuspiciousBooter, self).__init__(rec)
        self.idea["co_jsem"] = 'SuspiciousBooter'


# ---------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------


def convert_to_idea(rec, opts=None):
    try:
        rec["is_only_fqdn"]
        print('This is URL alert')
        bl_type = 'url_dns'

    except KeyError:
        print('This is IP alert')
        bl_type = 'ip'

    global bl_config
    if not bl_config:
        bl_config = load_config(opts.blacklist_config)

    current_bl = [val for key, val in bl_config[bl_type].items() if key == rec["blacklist_bmp"]][0]

    category_class = current_bl["category"].replace('.', '')
    module = __import__('__main__')

    category_class = getattr(module, category_class)

    category_instance = category_class(rec)

    print(category_instance.get_idea())


def load_config(config):
    """Load `config` file of blacklistfilter module (bl_downloader_config.xml).
    This file contains a list of blacklists, their names and URLs.

    load_config() returns dictionary, where the key is id (= 2**ID from file) and
    value is a dictionary of "name", "type", "source" and other parameters.
    """
    bls = {}
    with open(config, "r") as f:
        tree = xml.parse(f)

    ip_root_element = tree.find(".//array[@type='IP']")
    url_dns_root_element = tree.find(".//array[@type='URL/DNS']")

    ip_blacklists = list(ip_root_element)
    url_dns_blacklists = list(url_dns_root_element)

    for blacklists in [ip_blacklists, url_dns_blacklists]:
        bl_type = 'ip' if blacklists is ip_blacklists else 'url_dns'
        bls[bl_type] = {}

        for struct in blacklists:
            elems = list(struct)
            bl_id = None
            bl_name = None
            bl_category = None
            bl_source = None
            for el in elems:
                attr = el.attrib["name"]
                if attr == "name":
                    bl_name = el.text
                elif attr == "id":
                    bl_id = 2 ** (int(el.text) - 1)
                elif attr == "category":
                    bl_category = el.text
                elif attr == "source":
                    bl_source = el.text
            if not bl_id or not bl_name or not bl_category or not bl_source:
                sys.stderr.write("Incomplete configuration. " + str((bl_id, bl_name, bl_category)))
                break

            bls[bl_type][bl_id] = {"name": bl_name, "category": bl_category, "source": bl_source}

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


def ip_list2description(iplist):
    if type(iplist) == list:
        if len(iplist) <= 2:
            return ", ".join(iplist)
        else:
            return "{0}, {1}, and {2} more".format(iplist[0], iplist[1], len(iplist) - 2)
    elif type(iplist) == str:
        return iplist
    else:
        raise TypeError("ip_list2description() expects list or str argument.")


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
parser = argparse.ArgumentParser()
parser.add_argument('--blacklist-config', help="Set path to config file of blacklist downloader. Default: /etc/nemea/blacklistfilter/bl_downloader_config.xml", default="/etc/nemea/blacklistfilter/bl_downloader_config.xml")

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
