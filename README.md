# Single-file DNS resolver in pure C

It allows you to analyze DNS packets at a low level.

## Usage:

```bash
$ ./a.out <domain> [dns server]
```

## Example:

```bash
$ ./a.out google.com
Raw data packet (total 28 bytes sent):
85 34 01 00 00 01 00 00 00 00 00 00 06 67 6F 6F 
67 6C 65 03 63 6F 6D 00 00 01 00 01 

Raw data packet (total 124 bytes recieved):
85 34 81 80 00 01 00 06 00 00 00 00 06 67 6F 6F 
67 6C 65 03 63 6F 6D 00 00 01 00 01 C0 0C 00 01 
00 01 00 00 01 2C 00 04 4A 7D 83 64 C0 0C 00 01 
00 01 00 00 01 2C 00 04 4A 7D 83 71 C0 0C 00 01 
00 01 00 00 01 2C 00 04 4A 7D 83 66 C0 0C 00 01 
00 01 00 00 01 2C 00 04 4A 7D 83 65 C0 0C 00 01 
00 01 00 00 01 2C 00 04 4A 7D 83 8A C0 0C 00 01 
00 01 00 00 01 2C 00 04 4A 7D 83 8B 

Name:   google.com
Address: 74.125.131.100
Name:   google.com
Address: 74.125.131.113
Name:   google.com
Address: 74.125.131.102
Name:   google.com
Address: 74.125.131.101
Name:   google.com
Address: 74.125.131.138
Name:   google.com
Address: 74.125.131.139
```