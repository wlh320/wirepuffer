#include <cstdio>
#include <arpa/inet.h>
#include "shared.h"
#include "ipv6.h"

void parse_ipv6(packet *pkt, packet_info *pkt_info, bool is_full)
{
    ipv6_header *hdr = pkt->ipv6_hdr;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    // src ip
    inet_ntop(AF_INET6, &hdr->src_ip, src_ip, INET6_ADDRSTRLEN);
    pkt_info->src_addr = src_ip;
    // dst ip
    inet_ntop(AF_INET6, &hdr->dst_ip, dst_ip, INET6_ADDRSTRLEN);
    pkt_info->dst_addr = dst_ip;
    // protocol

    uint8_t *curr = reinterpret_cast<uint8_t*>(hdr) + sizeof (ipv6_header);
IPV6_AGAIN: // what? I use goto statement!
    ipv6_ext_header *ext = reinterpret_cast<ipv6_ext_header*>(curr);
    switch (hdr->next_header) {
    case IPPROTO_TCP:
        pkt->tcp_hdr = reinterpret_cast<tcp_header *>(curr);
        pkt_info->protocol = "TCP";
        break;
    case IPPROTO_UDP:
        pkt->udp_hdr = reinterpret_cast<udp_header *>(curr);
        pkt_info->protocol = "UDP";
        break;
    case IPPROTO_ICMP:
        pkt->icmpv4_hdr = reinterpret_cast<icmpv4_header *>(curr);
        pkt_info->protocol = "ICMP";
        break;
    case IPPROTO_ICMPV6:
        pkt->icmpv6_hdr = reinterpret_cast<icmpv6_header *>(curr);
        pkt_info->protocol = "ICMPv6";
        break;
    case IPPROTO_IP:
        hdr->next_header = ext->next_header; // sorry for change that
        curr += ext->ext_len;
        goto IPV6_AGAIN;
    default:
        // TODO not implemented
        break;
    }
    if (is_full) {
        QTreeWidgetItem *tree = ITEM("Internet Protocol Version 6");
        pkt_info->detail->addChild(tree);
//        tree->addChild(ITEM(QString("Traffic Class  %1").arg(toBinary(hdr->traffic_class_hi))));
        tree->addChild(ITEM(QString("Paylod Len --- %1").arg(ntohs(hdr->payload_len))));
        tree->addChild(ITEM(QString("Hop Limit ---- %1").arg(hdr->hop_limit)));
        tree->addChild(ITEM(QString("Source ------- %1").arg(src_ip)));
        tree->addChild(ITEM(QString("Destination -- %1").arg(dst_ip)));
        tree->addChild(ITEM(QString("Protocol ----- %1 (%2)").arg(pkt_info->protocol).arg(hdr->next_header)));
    }
    pkt->len -= (curr - reinterpret_cast<uint8_t*>(hdr));
}
