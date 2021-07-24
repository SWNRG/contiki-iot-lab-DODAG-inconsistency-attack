This is a fork from fit-iot-bab contiki https://github.com/iot-lab/contiki , which is a fork of contiki 3.0 The only changes are in file ../core/net/rpl/rpl-icmp6.c where the version of the DAO message is increased every time the (malicious) node sends a new message: buffer[pos++] = ++ (dag->version);

The attacker node DOES nothing per se.

Another idea is to use a standard contiki and insert a compile variable (#ifdef) sourounding the above line to enable it only for malicious nodes.

Examples and applied such attacks can be found in ASSET: https://github.com/SWNRG/ASSET

Dont forget to cite:
George Violettas, George Simoglou, Sophia Petridou, Lefteris Mamatas, A Softwarized Intrusion Detection System for the RPL-based Internet of Things networks, Future Generation Computer Systems, Volume 125, 2021, Pages 698-714, ISSN 0167-739X, https://doi.org/10.1016/j.future.2021.07.013.

/*********** George DODAG inconsistency ***************************/        
          
Changes are in file core/net/rpl/rpl-ext-header.c
The attacker node DOES nothing per se...
              
/* DODAG inconsistency paper "Addressing DODAG Inconsistency 
Attacks in RPL Networks" mentions:

The ‘O’ flag— indicates the expected direction of a packet. When set, 
the packet is intended for a descendant. Otherwise it is intended 
for a parent, towards the DODAG root.

The ‘R’ flag— indicates that a rank error was detected by a node 
forwarding the packet. A mismatch between the direction indicated by 
the ‘O’ flag and the rank of sending/forwarding node causes the flag 
to be set. The ‘R’ flag is used to repair this problem by setting it, 
in case it was not set previously, and forwarding the packet. 
Upon receiving a packet with the ‘R’ flag already set, the packet 
is discarded and the trickle timer used by RPL is reset.

A malicious node, part of an RPL network, can directly
attack its parent by sending data packets that have the ‘O’
and ‘R’ flags set. Since packets with the ‘O’ flag are intended
for descendant nodes, the receiving parent detects a DODAG
inconsistency. If the ‘R’ flag is also set, which is the case
during the attack, the received packet is dropped and the trickle
timer is reset */

UIP_EXT_HDR_OPT_RPL_BUF->flags |= RPL_HDR_OPT_DOWN;
UIP_EXT_HDR_OPT_RPL_BUF->flags |= RPL_HDR_OPT_RANK_ERR;

printf("George: ILLEGAL options 'O' & 'R' set. \n");
