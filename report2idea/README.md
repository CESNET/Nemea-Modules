# Example output of reporters

All examples are used for automatic test (in [test.sh](./test.sh)).
Information contained in the listed examples (e.g. IP addresses) is randomly generated or anonymized.

The output of reporters are conforming to [IDEA format](https://idea.cesnet.cz/en/index).

Each reporting module can store its output into file or send alerts into [Warden system](https://warden.cesnet.cz/) for incident sharing.

## Bruteforce detection

### Alerts from `brute_force_detection` module (will be published soon, it is still in private repository):

**SSH**

```json
{
    "DetectTime": "2015-12-14T23:18:50Z",
    "Category": [
        "Attempt.Login"
    ],
    "Target": [
        {
            "Port": 22,
            "Proto": [
                "tcp",
                "ssh"
            ]
        }
    ],
    "FlowCount": 30,
    "Description": "Multiple unsuccessful login attempts on SSH",
    "Format": "IDEA0",
    "Source": [
        {
            "IP4": [
                "1.2.3.6"
            ],
            "Proto": [
                "tcp",
                "ssh"
            ]
        }
    ],
    "ID": "59c85a23-11b6-4faf-9eff-55bfb5f7fda5",
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "brute_force_detector"
            ],
            "Name": "cz.cesnet.nemea.brute_force_detector"
        }
    ],
    "CreateTime": "2016-03-23T15:53:56Z"
}
```

**TELNET**

```json
{
    "DetectTime": "2015-12-14T23:18:50Z",
    "Category": [
        "Attempt.Login"
    ],
    "Target": [
        {
            "Port": 23,
            "Proto": [
                "tcp",
                "telnet"
            ]
        }
    ],
    "FlowCount": 30,
    "Description": "Multiple unsuccessful login attempts on TELNET",
    "Format": "IDEA0",
    "Source": [
        {
            "IP4": [
                "1.2.3.6"
            ],
            "Proto": [
                "tcp",
                "telnet"
            ]
        }
    ],
    "ID": "5f1ef384-6256-4a64-ade7-f3278476b965",
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "brute_force_detector"
            ],
            "Name": "cz.cesnet.nemea.brute_force_detector"
        }
    ],
    "CreateTime": "2016-03-23T15:53:56Z"
}
```

**RDP**

```json
{
    "DetectTime": "2015-12-16T18:02:58Z",
    "Category": [
        "Attempt.Login"
    ],
    "Target": [
        {
            "Port": 2179,
            "Proto": [
                "tcp",
                "vmrdp"
            ]
        }
    ],
    "FlowCount": 122,
    "Description": "Multiple unsuccessful login attempts on VMRDP",
    "Format": "IDEA0",
    "Source": [
        {
            "IP4": [
                "6.1.2.7"
            ],
            "Proto": [
                "tcp",
                "vmrdp"
            ]
        }
    ],
    "ID": "40c7901e-a516-4735-b614-7abe1ba946a6",
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "brute_force_detector"
            ],
            "Name": "cz.cesnet.nemea.brute_force_detector"
        }
    ],
    "CreateTime": "2016-03-23T15:53:56Z"
}
```

**VNC**

```json
{
    "DetectTime": "2015-12-16T18:02:58Z",
    "Category": [
        "Attempt.Login"
    ],
    "Target": [
        {
            "Port": 5900,
            "Proto": [
                "tcp",
                "vnc"
            ]
        }
    ],
    "FlowCount": 122,
    "Description": "Multiple unsuccessful login attempts on VNC",
    "Format": "IDEA0",
    "Source": [
        {
            "IP4": [
                "6.1.2.7"
            ],
            "Proto": [
                "tcp",
                "vnc"
            ]
        }
    ],
    "ID": "bff28754-a5ba-4eae-979c-0b40e7ec90e2",
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "brute_force_detector"
            ],
            "Name": "cz.cesnet.nemea.brute_force_detector"
        }
    ],
    "CreateTime": "2016-03-23T15:53:56Z"
}
```

### Alerts from the [sip_bf_detector](https://github.com/CESNET/Nemea-Detectors/tree/master/sip_bf_detector) module:

```json
{
   "Category": [
      "Attempt.Login"
   ],
   "Node": [
      {
         "Type": [
            "Flow",
            "Statistical"
         ],
         "SW": [
            "Nemea",
            "brute_force_detector"
         ],
         "Name": "sipbf"
      }
   ],
   "EventTime": "2017-01-05T16:04:36Z",
   "Target": [
      {
         "Port": [
            5060
         ],
         "IP4": [
            "128.175.220.114"
         ],
         "Proto": [
            "sip"
         ]
      }
   ],
   "Source": [
      {
         "Port": [
            5171
         ],
         "IP4": [
            "105.138.15.163"
         ],
         "Proto": [
            "sip"
         ]
      }
   ],
   "ID": "0f2e00f5-f1e0-4464-99ec-963bf055aba8",
   "DetectTime": "2017-02-03T18:43:50Z",
   "Description": "SIP BruteForce login attempt, user account: 5985@128.175.220.114",
   "ConnCount": 4380,
   "Format": "IDEA0",
   "CeaseTime": "2017-01-05T16:07:28Z",
   "CreateTime": "2017-02-03T18:43:50Z"
}
```

### Alerts from the [hoststatsnemea](https://github.com/CESNET/Nemea-Detectors/tree/master/hoststatsnemea) module:

```json
{
    "DetectTime": "2016-03-23T16:50:47Z",
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "HostStatsNemea"
            ],
            "Name": "cz.cesnet.nemea.hoststats"
        }
    ],
    "EventTime": "2016-03-22T12:12:51Z",
    "Description": "SSH dictionary/bruteforce attack",
    "ConnCount": 71,
    "CeaseTime": "2016-03-22T12:17:59Z",
    "Format": "IDEA0",
    "Category": [
        "Attempt.Login"
    ],
    "ID": "dd359048-6b12-4aea-9933-3565995566f5",
    "Source": [
        {
            "IP4": [
                "1.1.1.1"
            ]
        }
    ],
    "FlowCount": 142,
    "CreateTime": "2016-03-23T16:50:47Z",
    "Target": [
        {
            "Port": [
                22
            ],
            "Proto": [
                "tcp",
                "ssh"
            ]
        }
    ]
}
```

```json
{
    "DetectTime": "2016-03-23T16:50:47Z",
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "HostStatsNemea"
            ],
            "Name": "cz.cesnet.nemea.hoststats"
        }
    ],
    "EventTime": "2016-03-22T12:12:51Z",
    "Description": "SSH dictionary/bruteforce attack",
    "ConnCount": 62,
    "CeaseTime": "2016-03-22T12:17:54Z",
    "Format": "IDEA0",
    "Category": [
        "Attempt.Login"
    ],
    "ID": "4c819d23-2280-4c39-8446-f1d3611014c2",
    "FlowCount": 124,
    "CreateTime": "2016-03-23T16:50:47Z",
    "Target": [
        {
            "Port": [
                22
            ],
            "IP4": [
                "1.1.1.1"
            ],
            "Proto": [
                "tcp",
                "ssh"
            ]
        }
    ]
}
```

### Alerts from [voip_fraud_detection](https://github.com/CESNET/Nemea-Detectors/tree/master/voip_fraud_detection) module:

```json
{
    "Category": [
        "Attempt.Login"
    ],
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical",
                "Content"
            ],
            "SW": [
                "Nemea",
                "voip_fraud_detection"
            ],
            "Name": "cz.cesnet.nemea.voipfrauddetection"
        }
    ],
    "EventTime": "2016-03-10T09:45:54Z",
    "Target": [
        {
            "SIPTo": [
                "841111000@9.2.5.1:5060"
            ],
            "Proto": [
                "sip"
            ]
        }
    ],
    "SuccessfulCalls": 0,
    "TriedPrefixCount": 11,
    "ID": "2c51eb9a-e3e5-49f3-ac22-a40780a3961b",
    "DetectTime": "2016-03-10T10:45:36Z",
    "Description": "SIP Dial-plan guessing",
    "ConnCount": 11,
    "Format": "IDEA0",
    "Source": [
        {
            "UserAgent": [
                "Asterisk PBX 11.21.1"
            ],
            "SIPFrom": [
                ""
            ],
            "IP4": [
                "1.1.1.1"
            ],
            "Proto": [
                "sip"
            ]
        }
    ],
    "MaxPrefixLength": 9,
    "CreateTime": "2016-03-23T15:53:56Z"
}
```

## Communication tunnels over DNS

### Alerts from [dnstunnel_detection](https://github.com/CESNET/Nemea-Detectors/tree/master/tunnel_detection) module:

```json
{
    "Category": [
        "Anomaly.Connection"
    ],
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical",
                "Content"
            ],
            "SW": [
                "Nemea",
                "dnstunnel_detection"
            ],
            "Name": "cz.cesnet.nemea.dnstunnel"
        }
    ],
    "EventTime": "2016-02-27T13:35:19Z",
    "Note": "Example of used domain name: 7441696572e315fd97fe137ccdcf6418.clo.footprintdns.com",
    "Source": [
        {
            "IP4": [
                "1.1.2.1"
            ],
            "Proto": [
                "udp",
                "dns"
            ]
        }
    ],
    "ID": "94c2d208-9b71-4ae9-a45e-ed94cfe0015b",
    "DetectTime": "2016-02-27T13:41:33Z",
    "Description": "Communication tunnel over DNS observed in requests",
    "Format": "IDEA0",
    "CeaseTime": "2016-02-27T13:41:33Z",
    "FlowCount": 270,
    "CreateTime": "2016-03-23T15:53:56Z"
}
```

## Scanning

### Alerts from the [hoststatsnemea](https://github.com/CESNET/Nemea-Detectors/tree/master/hoststatsnemea) module:

```json
{
    "DetectTime": "2016-03-23T15:53:55Z",
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "HostStatsNemea"
            ],
            "Name": "hoststats"
        }
    ],
    "EventTime": "2016-02-10T21:28:20Z",
    "Description": "Horizontal port scan",
    "ConnCount": 243,
    "CeaseTime": "2016-02-10T21:31:27Z",
    "Format": "IDEA0",
    "Category": [
        "Recon.Scanning"
    ],
    "ID": "6f15d2ab-bd30-4720-b17f-8c9932b79193",
    "Source": [
        {
            "IP4": [
                "11.22.12.22"
            ],
            "Proto": [
                "tcp"
            ]
        }
    ],
    "FlowCount": 243,
    "CreateTime": "2016-03-23T15:53:55Z"
}
```

### Alerts from the [vportscan_detector](https://github.com/CESNET/Nemea-Detectors/tree/master/vportscan_detector) module:

```json
{
    "Category": [
        "Recon.Scanning"
    ],
    "Node": [
        {
            "AggrWin": "00:10:00",
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "vportscan_detector"
            ],
            "Name": "vportscan"
        }
    ],
    "EventTime": "2016-02-10T19:06:20Z",
    "Target": [
        {
            "IP4": [
                "4.2.5.21"
            ],
            "Proto": [
                "tcp"
            ]
        }
    ],
    "Source": [
        {
            "IP4": [
                "47.5.21.82"
            ],
            "Proto": [
                "tcp"
            ]
        }
    ],
    "ID": "fb52a974-6f01-49e1-b096-3427895ca700",
    "DetectTime": "2016-02-10T19:21:08Z",
    "Description": "Vertical scan using TCP SYN",
    "Format": "IDEA0",
    "CeaseTime": "2016-02-10T19:21:08Z",
    "FlowCount": 150,
    "CreateTime": "2016-03-23T15:53:55Z"
}
```

### Alerts from the [haddrscan_detector](https://github.com/CESNET/Nemea-Detectors/tree/master/haddrscan_detector) module:

```json
{
    "Category": [
        "Recon.Scanning"
    ],
    "Node": [
        {
            "AggrWin": "00:10:00",
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "haddrscan_detector"
            ],
            "Name": "haddrscan"
        }
    ],
    "EventTime": "2016-12-10T18:08:20Z",
    "Target": [
        {
            "Port": [
                54321
            ],
            "Proto": [
                "tcp"
            ]
        }
    ],
    "Source": [
        {
            "IP4": [
                "1.1.1.1"
            ],
            "Port": [
                12345
            ],
            "Proto": [
                "tcp"
            ]
        }
    ],
    "ID": "43ead176-e3a2-46f3-a92c-dfdddefc2bcf",
    "DetectTime": "2016-12-10T18:21:08Z",
    "Description": "Horizontal scan using TCP SYN",
    "Format": "IDEA0",
    "CeaseTime": "2016-12-10T18:21:08Z",
    "FlowCount": 250,
    "CreateTime": "2017-01-01T23:26:30Z"
}
```


## (D)DoS

### Alerts from the [hoststatsnemea](https://github.com/CESNET/Nemea-Detectors/tree/master/hoststatsnemea) module:

```json
{
    "DetectTime": "2016-03-23T16:50:47Z",
    "Node": [
        {
            "Type": [
                "Flow",
                "Statistical"
            ],
            "SW": [
                "Nemea",
                "HostStatsNemea"
            ],
            "Name": "cz.cesnet.nemea.hoststats"
        }
    ],
    "EventTime": "2016-03-22T15:36:20Z",
    "Target": [
        {
            "IP4": [
                "1.1.1.1"
            ],
            "Proto": [
                "udp",
                "dns"
            ]
        }
    ],
    "CeaseTime": "2016-03-22T15:41:19Z",
    "Format": "IDEA0",
    "Category": [
        "Availability.DoS"
    ],
    "ID": "aae3a758-7c41-4d97-ba18-bae575c1cc45",
    "FlowCount": 14631,
    "CreateTime": "2016-03-23T16:50:47Z",
    "Description": "1.1.1.1 received abnormally high number of large DNS replies - probably a victim of DNS amplification DoS attack"
}
```

### Alerts from the [amplification_detection](https://github.com/CESNET/Nemea-Detectors/tree/master/amplification_detection) module:

```json
{
    "Category": [
        "Availibility.DDoS"
    ],
    "Node": [
        {
            "SW": [
                "Nemea",
                "amplification_detection"
            ],
            "Name": "amplification"
        }
    ],
    "EventTime": "2015-10-26T08:05:05Z",
    "Target": [
        {
            "InPacketCount": 2798,
            "Proto": [
                "udp",
                "dns"
            ],
            "InFlowCount": 933,
            "IP4": [
                "43.231.6.123"
            ],
            "InByteCount": 3882916
        }
    ],
    "Source": [
        {
            "InFlowCount": 1294,
            "Proto": [
                "udp",
                "dns"
            ],
            "OutFlowCount": 933,
            "OutByteCount": 3882916,
            "InByteCount": 84110,
            "InPacketCount": 1294,
            "IP4": [
                "195.113.82.246"
            ],
            "OutPacketCount": 2798
        }
    ],
    "PacketCount": 2798,
    "Type": [
        "Flow",
        "Statistical"
    ],
    "ID": "ed67f85a-5908-4e64-9359-a5e620ee2b59",
    "DetectTime": "2015-10-26T08:20:11Z",
    "Description": "DNS amplification",
    "Format": "IDEA0",
    "CeaseTime": "2015-10-26T08:20:11Z",
    "ByteCount": 3882916,
    "FlowCount": 933,
    "CreateTime": "2016-03-23T15:53:55Z"
}
```


## Botnet communication

### Alerts from the [blacklistfilter](https://github.com/CESNET/Nemea-Detectors/tree/master/blacklistfilter) module:

```json
{
    "Category": [
        "Intrusion.Botnet"
    ],
    "Node": [
        {
            "Type": [
                "Flow",
                "Blacklist"
            ],
            "SW": [
                "Nemea",
                "ipblacklistfilter"
            ],
            "Name": "cz.cesnet.nemea.ipblacklistfilter"
        }
    ],
    "EventTime": "2016-03-11T00:08:55Z",
    "Note": "Source IP 157.7.170.62 was found on blacklist.",
    "Source": [
        {
            "Type": [
                "Botnet"
            ],
            "IP4": [
                "10.0.2.15"
            ],
            "Proto": [
                "icmp"
            ]
        },
        {
            "Type": [
                "Botnet",
                "CC"
            ],
            "IP4": [
                "157.7.170.62"
            ],
            "Proto": [
                "icmp"
            ]
        }
    ],
    "PacketCount": 1,
    "ID": "006eecc0-aa9f-4c7b-aff6-49eaf7d45538",
    "DetectTime": "2016-03-11T00:08:55Z",
    "Description": "157.7.170.62 which is on Zeus blacklist connected to 10.0.2.15.",
    "Format": "IDEA0",
    "CeaseTime": "2016-03-11T00:08:55Z",
    "ByteCount": 84,
    "CreateTime": "2016-03-23T15:53:56Z"
}
```

```json
{
    "Category": [
        "Intrusion.Botnet"
    ],
    "Node": [
        {
            "Type": [
                "Flow",
                "Blacklist"
            ],
            "SW": [
                "Nemea",
                "ipblacklistfilter"
            ],
            "Name": "cz.cesnet.nemea.ipblacklistfilter"
        }
    ],
    "EventTime": "2016-03-11T00:08:55Z",
    "Note": "Destination IP 157.7.170.62 was found on blacklist.",
    "Source": [
        {
            "Type": [
                "Botnet",
                "CC"
            ],
            "IP4": [
                "157.7.170.62"
            ],
            "Proto": [
                "icmp"
            ]
        },
        {
            "Type": [
                "Botnet"
            ],
            "IP4": [
                "10.0.2.15"
            ],
            "Proto": [
                "icmp"
            ]
        }
    ],
    "PacketCount": 2,
    "ID": "5c0bfe4c-c2ef-4442-8559-15a1da3bd560",
    "DetectTime": "2016-03-11T00:08:56Z",
    "Description": "10.0.2.15 connected to 157.7.170.62 which is on Zeus blacklist.",
    "Format": "IDEA0",
    "CeaseTime": "2016-03-11T00:08:56Z",
    "ByteCount": 168,
    "CreateTime": "2016-03-23T15:53:56Z"
}
```

