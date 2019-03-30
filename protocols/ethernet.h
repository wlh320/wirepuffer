#ifndef ETHERNET_H
#define ETHERNET_H

#include <cstdint>

#define	ETHERTYPE_IP    0x0800	/* IP protocol version 4 */
#define ETHERTYPE_ARP 	0x0806
#define	ETHERTYPE_IPV6	0x86dd	/* IP protocol version 6 */

#define ETHER_ADDR_LEN  6
#define ETHER_HDRLEN    14
struct ether_header
{
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
};

#include "packet.h"
void parse_ethernet(packet *pkt, packet_info *pkt_info);

#endif
