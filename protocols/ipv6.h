#ifndef IPV6_H__
#define IPV6_H__
#include <cstdint>

struct ipv6_header
{
    // little endien
    uint8_t   traffic_class_hi : 4; // traffic class
    uint8_t   version : 4;
    uint8_t   flow_label_hi : 4;
    uint8_t   traffic_class_lo : 4;
    uint16_t  flow_label_lo;
    uint16_t  payload_len;
    uint8_t   next_header;
    uint8_t   hop_limit;
    uint32_t  src_ip[4];
    uint32_t  dst_ip[4];
};

#include "packet.h"
void parse_ipv6(packet *pkt, packet_info *pkt_info, bool is_full = false);

#endif

