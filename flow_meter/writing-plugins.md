# Guide to create NTP plugin for flow_meter

## Kickstart

1. Create files `ntpplugin.h` and `ntpplugin.cpp`
2. Define UR_FIELDS in ntpplugin.cpp (inspired by [./sipplugin.cpp](./sipplugin.cpp))
3. Define own class inherited from FlowRecordExt (defined in [./flowifc.h](./flowifc.h))
   e.g. struct FlowRecordExtNTP : FlowRecordExt
4. Implement FlowRecordExtNTP::fillUnirec() that fills values of UniRec message fields
   e.g. like in [./sipplugin.h](./sipplugin.h)
5. Define the second own class inherited from FlowCachePlugin (defined in [./flowchageplugin.h](./flowchageplugin.h))
   e.g. NTPPlugin : public FlowCachePlugin (like in [./sipplugin.h](./sipplugin.h))
6. Implement NTPPlugin::get_unirec_field_string with textual list of UniRec fields that are filled by plugin
   e.g. like in [./sipplugin.cpp](./sipplugin.cpp)
7. Modify [./flowifc.h](./flowifc.h): extend extTypeEnum
8. Modify [./flow_meter.cpp](./flow_meter.cpp): add own plugin into -p parameter parsing
9. Do not forget to update help string for -p parameter in [./flow_meter.cpp](./flow_meter.cpp)
10. Add new files into [./Makefile.am](./Makefile.am) sources

## Exporting real data

It is needed to lookup the real information in packets.
`FlowCachePlugin` class in [flowcacheplugin.h](flowcacheplugin.h) defines methods that can be override by the new plugin.
The "live cycle" of exporting is as follows:
* init (plugin)
* post_create()
* pre_update()
* post_update()
* pre_export()
* finish()

See source code file ([flowcacheplugin.h](flowcacheplugin.h)) for detailed information.
