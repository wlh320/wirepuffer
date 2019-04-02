#include <cstdio>
#include <QTreeWidgetItem>

#include "parser.h"
#include "shared.h"

#include "ethernet.h"

#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"

#include "tcp.h"
#include "udp.h"
#include "icmp.h"

#include "dns.h"


packet_info* parse(uint len, uchar *raw, bool is_full)
{
    packet *pkt = new packet;
    packet_info *pkt_info = new packet_info;
    pkt->len = len;
    pkt->ether_hdr = reinterpret_cast<ether_header*>(raw);
    pkt_info->detail = new QTreeWidgetItem(QStringList("Packet Info"));
    // rawhex
    if (is_full) {
        pkt_info->rawhex = hexdump(len, raw);
    }

    // layer 2
    parse_ethernet(pkt, pkt_info);

    // layer 3
    if (pkt->arp_hdr != nullptr) {
        parse_arp(pkt, pkt_info);
    } else if (pkt->ipv4_hdr != nullptr) {
        parse_ipv4(pkt, pkt_info, is_full);
    } else if (pkt->ipv6_hdr != nullptr) {
        parse_ipv6(pkt, pkt_info, is_full);
    }

    // layer 4
    if (pkt->tcp_hdr != nullptr) {
        parse_tcp(pkt, pkt_info);
    } else if (pkt->udp_hdr != nullptr) {
        parse_udp(pkt, pkt_info);
    } else if (pkt->icmpv4_hdr != nullptr) {
        parse_icmpv4(pkt, pkt_info);
    } else if (pkt->icmpv6_hdr != nullptr) {
        parse_icmpv6(pkt, pkt_info);
    }

    // layer 5 TODO
    // Not Implemented
    if (pkt->dns_hdr != nullptr) {
        parse_dns(pkt, pkt_info);
    }

    delete pkt;
    return pkt_info;
}
