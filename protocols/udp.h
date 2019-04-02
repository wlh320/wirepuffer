#ifndef UDP_H
#define UDP_H
#include <cstdint>

struct udp_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};

#include "packet.h"

void parse_udp(packet *pkt, packet_info *pkt_info);

#endif // UDP_H
