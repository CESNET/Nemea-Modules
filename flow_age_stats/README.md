---
# Flow Age Stats module - README

## Description
This module is used for making statistics about the age of incoming flow data. The statistics produced are minimal, maximal and average values for both first time the flow is encountered and the last time the flow is encountered. 

Additionally the module can output two text files (time_first.txt, time_last.txt) that make up a table of three columns. First is the max age of the flow. Second is the percentage of flows that are in that age group. Third is the flow count. 

## Interfaces
- Input: One UniRec interface
    - Template MUST contain fields TIME_FIRST and TIME_LAST
- Output: None

## Parameters
- '-f int'       Creates or opens a file where the histograms will be outputed. Int must have the value 1. (Caution - the module will overwrite files labeled time_first.txt, time_last.txt)

## Graphs
This module also comes with a script that makes use of GNUplot to make graphs from the data that is outputed into files. You can see how the graph looks like below.

![ExampleGraph](example.png)
