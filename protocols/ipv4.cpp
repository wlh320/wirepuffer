#include <cstdio>
#include <arpa/inet.h>
#include "shared.h"
#include "ipv4.h"

void parse_ipv4(packet *pkt, packet_info *pkt_info, bool is_full)
{
    ipv4_header *hdr = pkt->ipv4_hdr;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    // src ip
    inet_ntop(AF_INET, &hdr->src_ip, src_ip, INET_ADDRSTRLEN);
    pkt_info->src_addr = src_ip;
    // dst ip
    inet_ntop(AF_INET, &hdr->dst_ip, dst_ip, INET_ADDRSTRLEN);
    pkt_info->dst_addr = dst_ip;

    uint8_t *curr = reinterpret_cast<uint8_t*>(hdr) + sizeof (ipv4_header);
    // protocol
    switch (hdr->protocol) {
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
    }
    if (is_full) {
        QTreeWidgetItem *tree = ITEM("Internet Protocol Version 4");
        pkt_info->detail->addChild(tree);

        char tmp[256];

        tree->addChild(ITEM(QString("Header Len --- %1 bytes").arg(hdr->hdrlen * 4)));
        tree->addChild(ITEM(QString("TOS + ECN ---- %1").arg(toBinary(hdr->tos))));
        tree->addChild(ITEM(QString("Total Len ---- %1").arg(ntohs(hdr->tot_len))));
        sprintf(tmp, "Flags -------- 0x%04X", hdr->frag_off);
        tree->addChild(ITEM(tmp));
        tree->addChild(ITEM(QString("TTL ---------- %1").arg(hdr->ttl)));
        sprintf(tmp, "Checksum ----- 0x%04X", ntohs(hdr->checksum));
        tree->addChild(ITEM(tmp));
        tree->addChild(ITEM(QString("Source ------- %1").arg(src_ip)));
        tree->addChild(ITEM(QString("Destination -- %1").arg(dst_ip)));
        tree->addChild(ITEM(QString("Protocol ----- %1 (%2)").arg(pkt_info->protocol).arg(hdr->protocol)));
    }
    pkt->len -= (curr - reinterpret_cast<uint8_t*>(hdr));
}
