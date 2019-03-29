#ifndef IPV4_H__
#define IPV4_H__

#include <cstdint>


struct ipv4_header
{
    // little endien
    uint8_t  hdrlen : 4;
    uint8_t  version : 4;
    uint8_t  tos; // differentiated services field
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};


//Macros for the ip_off field
#define IP_RF        0x8000    // reserved fragment flag
#define IP_DF        0x4000    // dont fragment flag
#define IP_MF        0x2000    // more fragments flag

#define IP_OFFMASK   0x1fff    // mask for fragmenting bits
#define IP_OFFSET(ip) ((ntohs((ip)->frag_off)) & IP_OFFMASK) // the fragment offset

#include "packet.h"
void parse_ipv4(packet *pkt, packet_info *pkt_info, bool is_full = false);

#endif
