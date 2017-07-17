# Toucan-IDS

An Intrusion Detection System written in Python.

Toucan is currently a monitor to defend against man in the middle attacks (Both IPv4/IPv6 attacks) on a wireless network. For IPv4, when an attacker is discovered sending a gratuitous ARPs, Toucan will 'un-poison' the victim and the default gateway by sending out defensive ARPs with their original logged L2 addresses, and will then deauth the attacker off of the network and blacklist their L2 address. Additionally, toucan supports IPv6 spoofing defense by monitoring for gratuitous neighbor advertisements (since there is no ARP in IPv6).

*I have included an example log file also in which I ran the program on a /24 network and did an arp-scan just to generate some activity

Blue team best team
