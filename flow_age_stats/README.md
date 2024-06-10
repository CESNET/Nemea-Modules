---
# Flow Age Stats module - README

## Description
This module is used for making statistics about the age of incoming flow data. The statistics produced are minimal, maximal and average values for both first time the flow is encountered and the last time the flow is encountered. 

Additionally the module can output a histogram for time first and time last. The -f argument needs to be specified, so that the module knows where to put the data.

## Interfaces
- Input: One UniRec interface
    - Template MUST contain fields TIME_FIRST and TIME_LAST
- Output: None

## Parameters
- '-f <FILE>'       Creates or opens a file where the histograms will be outputed.