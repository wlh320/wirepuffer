#ifndef ICMPV4_H
#define ICMPV4_H
#include <cstdint>

struct icmpv4_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t body;
};

struct icmpv6_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t body;
};

#define ICMP_TYPE_ECHO_REPLY  0
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_TYPE_TRACEROUTE 30
#define ICMP_CODE_DEST_UNREACH_NET 0
#define ICMP_CODE_DEST_UNREACH_HOST 1
#define ICMP_CODE_DEST_UNREACH_PRO 2
#define ICMP_CODE_DEST_UNREACH_PORT 3

#include "packet.h"

void parse_icmpv4(packet *pkt, packet_info *pkt_info);
void parse_icmpv6(packet *pkt, packet_info *pkt_info);

#endif // ICMPV4_H
