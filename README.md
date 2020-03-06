UCLA CS118 Project (Simple Router)
====================================

For more detailed information about the project and starter code, refer to the project description on CCLE.

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restarted, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## Report

###### Group members:

**Jiangtao Chen, UID: 305429047**

Jiangtao Chen wrote the code in simple-router.cpp, handled the logic of the ICPM protocol.

**Yunhao Ji, UID: 605301740**

Yunhao Ji wrote the code of ARP protocol and handled the logic of the routing table lookup and ARP cache lookup.

## High level Design

This assignment runs on the top of Mininet that build by Stanford. Following the the emulate topology of a single network, we are required to implement the logic of a simple router. In this test, we mainly designed four parts codes: handle Ethernet frames, handle ARP packets, handle IPv4 packets and handle ICMP packets.

Every time the router receives a packet, `handlePacket()` function will parse its Ethernet header and check if the packet is a IPv4 packet or a ARP request packet. For the later case, the `handleArpPacket()` function is called to handle either APR request packet or ARP reply packet.

 If the packet is a IPv4 packet, the `handleIpPacket()` is called to check whether the packet's IP destination address is router's own IP address or  the other IP address. If the IP destination address is one of router's IP address, this packet could be a ICMP packet and consequently be sent into `handleIcmpPacket()` function which can send out ICMP echo reply packet, ICMP time exceeded packet and ICMP port unreachable packet. 

If  IPv4 packet is not sent to router, it should be properly forwarded. The `handleIpPacket()` function will recalculate the checksum and look up destination IP address in its routing table using longest-match algorithm. If the destination IP address is not in the routing table, the router will drop the packet. Otherwise, the router will look up the gateway mac address in ARP cache. if router can not find mac address in ARP cache, it will queue the origin packet in buffer and periodically call `handle_arpreq()` function to send ARP request massage to next hop. When router receives a ARP reply massage from the next hop, it will update the ARP cache and send the queuing packet out.

## Problems and Solutions 

The most hard part of this assignment is to make the mutual logic between each protocols clear. When we were testing the logic of the ICMP packets, the client could not correctly parse the packets. We found the problem is because the  `ip_len` part is not include the newly payload of the ICMP packet. When we changed the `ip_len` part to the correct one, the problem got solved.  

Another problem is about the usage of `htons()` function. This format caused some confusion at the first place.

We also found that although the ICMP time exceeded packet and port unreachable packet both can be used in the purpose of traceroute, the former would actually cause some issue when we run traceroute command. 