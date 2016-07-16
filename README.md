# NEMEA Modules

This repository contains basic modules of the [NEMEA system](https://github.com/CESNET/Nemea).
The modules and their functionality/purposes are:

* [logger](logger): export messages into CSV
* [logreplay](logreplay): replay stored CSV
* [nfreader](nfreader): replay stored nfdump file(s)
* [flow_meter](flow_meter): simple flow exporter from network interface controller (NIC) or PCAP file
* [unirecfilter](unirecfilter): filtering module
* [anonymizer](anonymizer): module for anonymization of flow records
* [traffic_repeater](traffic_repeater): flow repeater module (e.g. for interconnection of modules using different types of communication interfaces)
* [flowcounter](flowcounter): simple example of flow counting module
* [report2idea](report2idea): reporting modules that receive alerts from detectors and store them into database (MongoDB), file or send them into Warden
* [merger](merger): module for joining multiple input streams of messages into one output stream of messages
* [debug_sender](debug_sender): interactive tool (in Python) for creation and sending own messages/flow records
