# Device classifier module - README

## Description
This NEMEA module classifies devices according to their behavior on the network. 

The module associates each IP address with none, one or more *labels*. Labels should describe how a device (associated with an IP address) behave on the network. Output is based on traffic statistics measured within a time period. Results are printed to the standard output and can be optionally exported to a JSON file. 

The module offers a *training mode*, in which new labels can be learned by providing labeled examples. The classification performance with the existing labels can be also improved via this mode.

## Interfaces
- Input: 1
- Output: 0

## Parameters
### Module specific parameters
  - `-a`             Do not discard collected statistics each time the output is generated.
  - `-f FILE`        Classify only IP addresses (or subnets) specified in `FILE`.
  - `-F FILE`        Save results to `FILE` in JSON format.
  - `-l`             Print a list of known labels and exit.
  - `-m MINUTES`     Period after which the output is generated (default 0 = no period)
  - `-p N`           Add only devices with number of peers >= `N` to the output.
  - `-t FILE`        Run in a training mode. Training rules are specified in `FILE`.

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Classification and Output
Devices are classified right before an output is generated. An output of a classifier is based on the statistics measured up to this moment. The following labels are available in the default set:

- SERVER
- CLIENT
- HTTP
- FTP
- MAIL
- NTP
- SIP
- DNS
- RDP
- SSH

*Note: The set can be easily extended using labeled network traffic. See the Training section.*

Following are various cases in which the classification is performed:

- A time period has been specified by a user. Devices are classified repeatedly after this period. (\*)
- The main loop is interrupted, i.e. the process is terminated by the
system. Devices are classified unless a time interval has been specified.
- The signal `SIGUSR1` is sent to the module. This allows to classify devices
at any moment during runtime without interrupting the module.
- An end-of-file (`EOF`) message is received at the input interface. This
occurs when the end of the file with stored flows is reached.

(\*) This means each time the difference between the field `TIME_FIRST` of a flow and the time of the last generated output is greater than the specified period.

The results of classification are printed by default to the standard output. Optionally, the results can be exported to a JSON file.

### Standard output
Devices are printed on separate lines as tuples `ip_address\tlabel_1,label_2,...,label_n`. The output may be regarded as a tab-delimited CSV format.

### JSON
If the `-F` flag is specified, the output is also duplicated to a JSON file. 

In a single output, labeled devices are stored as items in a JSON array:

     [
       { "ip_address" : "ip_addr_1", "label" : ["label_1", "label_2", ..., "label_m"] },
       { "ip_address" : "ip_addr_2", "label" : [...] },
       ...
       { "ip_address" : "ip_addr_n", "label" : [...] }
     ]

All the outputs are stored in a parent JSON array.

## Filtering
To include only specific IP addresses in the output, a filter can be specified in file. Each line in file contains an IP address (or subnet) to be tracked:

    ip_addr_1
    ip_addr_2
    ...
    ip_addr_n

Each item `ip_addr_i` is an IPv4 address in standard format (e.g. `192.168.1.2`) or IPv4 address with subnet mask (e.g. `192.168.1.0/24`).

*Note: The filter does not apply to peer IP addresses. All the network traffic is still processed for the tracked IP addresses.*

## Training
To improve perfomance of the classifier or to add entirely new labels, the module can be launched in training mode. In this mode, the traffic of labeled IP addresses is saved and supplied to the learning algorithm. Each line contains an IP address (or subnet) and a label:

    ip_addr_1 label_1
    ip_addr_2 label_2
    ...
    ip_addr_n label_n

Each item `ip_addr_i` is an IPv4 address in standard format (e.g. `192.168.1.2`) or IPv4 address with subnet mask (e.g. `192.168.1.0/24`).

Each item `label_i` is an alphanumeric string. It can be either one of the existing labels (see the parameter `-l`) or a new one.

After the traffic data is collected (an `EOF` is received or the module is stopped), training is started automatically after confirmation. It can be also launched manually by running the script `./train.sh`.

*Note: Training can take several minutes, depending on the number of labels.*

## Implementation
This module uses [LIBSVM](https://www.csie.ntu.edu.tw/~cjlin/libsvm/index.html) for device classification. The library is an open-source C implementation of Support Vector Machines, a supervised machine learning classification algorithm.

## Usage

    ./device_classifier -i IFC_SPEC [-a] [-f file] [-F file] [-l] [-m minutes] [-p peers] [-t file]`

## Examples

1) *Basic classification*

    ./device_classifier -i u:localhost:test

The simplest way to launch the module for classification. The module waits for network flows in UniRec format on the interface specified by the parameter `-i` (in this case a UNIX socket `localhost:test`). The network flows can be supplied e.g. by the `logreplay` module. All devices are classified. The results are printed to the standard output when the module is interrupted.

2) *Classification with additional options*

    ./device_classifier -i u:localhost:test -m 360 -p 5 -f "list_of_ips.txt"

The module is launched with additional options. The results are printed periodically after 360 minutes to the standard output. The output is also filtered: only a set IP addresses specified in a file *list_of_ips.txt* is tracked. From the set, only the IP addresses with number of peers >= 5 are printed.

3) *Training mode*

    ./device_classifier -i u:localhost:test -t "list_of_labeled_ips.txt"

The module is launched in training mode. The module now processes only network flows containing the IP addresses specified in file *list_of_labeled_ips.txt*. In this mode, the module **does not classify** any IP addresses - on the opposite, the IP addresses **have to be already labeled** in the file. After data is collected, the training is launched. The next time the module is launched in normal mode, the classifier will use also the new data.

4) *List of known labels*

    ./device_classifier -i u:localhost:test -l

The module prints a list of known labels and exit. The input interface is specified only because it is required by the TRAP library.