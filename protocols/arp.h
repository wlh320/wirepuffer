#ifndef ARP_H
#define ARP_H

#include <cstdint>
struct arp_header
{
    uint16_t	hardware;		/* Format of hardware address.  */
    uint16_t	protocol;		/* Format of protocol address.  */
    uint8_t		hlen;		/* Length of hardware address.  */
    uint8_t		plen;		/* Length of protocol address.  */
    uint16_t	opcode;		    /* ARP opcode (command).  */
};

#define ARP_HARDWARE_TYPE_ETHERNET    1
#define ARP_PROTOCOL_TYPE_IPV4        0x0800

#define ARP_MAC_LENGTH				  6
#define ARP_IPv4_LENGTH				  4

#define ARP_OPCODE_REQUEST            1
#define ARP_OPCODE_REPLY              2

#include "packet.h"

void parse_arp(packet *pkt, packet_info *pkt_info);

#endif // ARP_H
