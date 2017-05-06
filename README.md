# eyespy
## Introduction
(I wrote this as an excuse to play around with the scapy libaries.) An incomplete tool designed to audit the hosts on your local lan segment by peforming a series of detection methods including -

+ arp sweep / arping to obtain ip and mac addresses / interface card vendor
+ arp poisioning to intercept TCP traffic and inject into p0f for operating system identification and listening services
+ port scanning to identify services 
+ ?

## Installation

### Requirements
1. python (2.7+)
2. [scapy libaries](http://www.secdev.org/projects/scapy/)
3. [compiled p0f binary](http://lcamtuf.coredump.cx/p0f3/)

### Running
eyespy is run with the following arguments -
```
./eyes.py -i <interface> -n <network/subnet bits>
```

On execution a table is constantly updated with newly discoverd hosts and services -

```
./eyes.py -i en0 -n 192.168.1.0/24

IP              NIC Vendor   OS                TCP ports
192.168.1.33         Apple      MacOS X 10.9
192.168.1.25      LgElectr   Linux 2.2.x-3.x
192.168.1.21       Buffalo    Windows 7 or 8   135,139,445 
192.168.1.1       JuniperN      Unknown   22
192.168.1.8          Apple          Mac OS X
```

### Disclaimer

Use at your own risk. By using this tool you take full responsibility for it's use. 
