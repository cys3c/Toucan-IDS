# Toucan-WIDS

A (in development) Wireless Intrusion Detection System written in Python.

Toucan is currently a monitor to defend against arp-spoofing, or man in the middle attacks on a wireless network running IPv4. My goal is to make this the first WIDS that can "attack back". When an attacker is discovered sending a gratuitous ARPs, Toucan will 'un-poison' the victim and the default gateway by sending out defensive ARPs with their original logged L2 addresses, and will then deauth the attacker off of the network and blacklist their L2 address. 

I have included an example log file also in which I ran the program on a /24 network and did an arp-scan just to generate some activity (which is why there are 250 or so requests in the file all at once)
