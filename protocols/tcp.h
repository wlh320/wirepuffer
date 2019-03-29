#ifndef TCP_H
#define TCP_H
#include <cstdint>
struct tcp_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    // little endien
    uint16_t res1 : 4;
    uint16_t doff : 4;
    uint16_t fin : 1;
    uint16_t syn : 1;
    uint16_t rst : 1;
    uint16_t psh : 1;
    uint16_t ack : 1;
    uint16_t urg : 1;
    uint16_t ece : 1;
    uint16_t cwr : 1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

#include "packet.h"
void parse_tcp(packet *pkt, packet_info *pkt_info);
#endif // TCP_H
