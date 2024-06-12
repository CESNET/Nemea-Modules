# Flow Age Stats module - README

## Description
This module is used for making statistics about the age of incoming flow data. The statistics produced are minimal, maximal and average values of the differences between the time a flow was received and its TIME_FIRST and TIME_LAST timestamps.

Additionally, the module can output histograms of flow age distribution. These are written as two text files (time_first.txt, time_last.txt) that each have a table of three columns. First is the max age of the flow (the end of bin range). Second is the percentage of flows that are in that age group. Third is the flow count. By default, the bins are 0-1s, 1s-10s, 10s-20s, ... 590s-600s, >600s.

## Interfaces
- Input: One UniRec interface
    - Template MUST contain fields TIME_FIRST and TIME_LAST
- Output: None

## Parameters
- '-t'       If specified, the module writes a file where the tables will be outputted. (Caution - the module will overwrite files labeled time_first.txt, time_last.txt)

## Graphs
This module also comes with a script that makes use of GNUplot to make graphs from the data that is outputted into files. You can see how the graph looks like below.

![ExampleGraph](example.png)

