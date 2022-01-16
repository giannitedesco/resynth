# resynth: A Network Packet Synthesis Language

[![Latest Version](https://img.shields.io/crates/v/resynth)](https://crates.io/crates/resynth/)
[![Documentation](https://img.shields.io/docsrs/resynth)](https://docs.rs/resynth/latest/resynth/)

## About
Resynth is a packet synthesis language. It produces network traffic (in the
form of pcap files) from textual descriptions of traffic. It enables
version-controlled packets-as-code workflows which can be useful for various
packet processing, or security research applications such as DPI engines, or
network intrusion detection systems.


## Examples
Here is how you might represent an HTTP request and response in resynth:

```
import ipv4;
import dns;
import text;

dns::host(192.168.0.1, "www.scaramanga.co.uk", ns: 8.8.8.8, 109.107.38.8);

let http = ipv4::tcp::flow(
  192.168.0.1:32768,
  109.107.38.8:80,
);

http.open();

http.client_message(
  text::crlflines(
    "GET / HTTP/1.1",
    "Host: www.scaramanga.co.uk",
    text::CRLF,
  )
);

http.server_message(
  text::crlflines(
    "HTTP/1.1 301 Moved Permanently",
    "Date: Sat, 17 Jul 2021 02:55:05 GMT",
    "Server: Apache/2.4.29 (Ubuntu)",
    "Location: https://www.scaramanga.co.uk/",
    "Content-Type: text/html; charset=iso-8859-1",
    text::CRLF,
  ),
);

http.server_close();
```

You can compile this to a pcap file with the command `resynth http.rsyn` - a
file called `http.pcap` will be created.


## Currently Supported Protocols
Not only can you write arbitrary TCP, UDP and ICMP packets but there are also
language modules for crafting packets for the following protocols:
- DNS (fairly mature, but could do with adding support for more record types)
- TLS (early stages, still need support for SSL2 and common extensions,
  although you can craft arbitrary TLS frames)
- IO packets can be crafted which include the contents of external files


## Why not use $OTHER\_TOOL?
- Scapy and python-based packet generation frameworks: they are incredibly slow
  for my intended use-cases (fuzz-testing, live high-speed packet-generation),
  even by the standards of what is possible in a pure python program. For very
  high-rate applications, I don't think it would be possible to automatically
  and transparently optimize scapy programs without adding some other layer
  designed specifically to speed things up.
- flowsynth: Flowsynth is really nice, and a big source of inspiration for
  this. But it lacks support for higher-level protocols and that little bit of
  extensibility which I really need.


## Future Directions
I plan to combine this with a DPDK-based packet generator in order to build a
network performance-testing suite (think T-Rex). The idea would be to add a
multi-instancing feature to the language to scale up the number of flows. The
resynth programs would be compiled in to a set of pre-canned packet templates
which could just be copied in to the tx ring-buffer with fields (eg. IP
addresses and port numbers) modulated. This would move all of the expensive
work out of the packet transmit mainloop and allow us to generate traffic at
upwards of 20Gbps per CPU.

The language is pretty bare-bones right now. But I plan to add:
- More builtin types: eg. signed integers, booleans, integers of various widths
- An operator to concatenate ip/port into a sockaddr
- An operator for concatenating buffers

I plan to add support for the following protocols to the standard library:
- Support for PMTU and segmentization of TCP messages
- Decent support for generating IP fragments
- VXLAN
- More direct support for HTTP
- SMB2
- ARP
- DCE-RPC
- More exotic TCP/IP interactions and better ICMP support
