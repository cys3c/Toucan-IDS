# Toucan-WIDS
An in development Wireless Intrusion Detection System

Toucan is currently a monitor to defend against arp-spoofing, or man in the middle attacks on a wireless network running IPv4. My goal is to make this the first WIDS that can "attack back". When an attacker is discovered sending a gratuitous ARPs, Toucan will 'un-poison' the victim and the default gateway by sending out defensive ARPs with their original logged L2 addresses, and will then deauth the attacker off of the network and blacklist their L2 address. 

What needs to be added:
1. Deauth capability
2. Custom alert protocol that can be sent to a server which will be monitored in a web console
3. Web console
