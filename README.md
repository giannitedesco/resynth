# resynth: A Network Packet Synthesis Language

## About
Resynth is a packet synthesis language. It produces network traffic (in the form
of pcap files) from textual descriptions of traffic. It enables
version-controlled packets-as-code workflows which can be useful for various
packet processing, or security research applications such as DPI engines, or
network intrusion detection systems.


## Examples
Here is how you might represent an HTTP request and response in esynth:

```
import ipv4;
import text;

let conn = ipv4::tcp::flow(
  192.168.0.1:32768,
  109.107.38.8:80,
);

conn.open();

conn.client_message(
  text::crlflines(
    "GET / HTTP/1.1",
    "Host: www.scaramanga.co.uk",
    text::CRLF,
  )
);

conn.server_message(
  text::crlflines(
    "HTTP/1.1 301 Moved Permanently",
    "Date: Sat, 17 Jul 2021 02:55:05 GMT",
    "Server: Apache/2.4.29 (Ubuntu)",
    "Location: https://www.scaramanga.co.uk/",
    "Content-Type: text/html; charset=iso-8859-1",
    text::CRLF,
  ),
);

conn.close();
```

You can compile this to a pcap file with the command `resynth http.rsy` - a
file called `http.pcap` will be created.


## Why not use $OTHER\_TOOL?
- Scapy and python-based packet generation framwworks: they are incredibly slow
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

The language is incredibly bare-bones right now. But I plan to add first-class support for:
- DNS
- ICMP
- TLS
- HTTP
- ARP
- SMB2
- DCE-RPC
- More exotic TCP/IP interactions
- Decent support for generating IP fragments
