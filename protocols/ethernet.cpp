#include <arpa/inet.h>
#include "shared.h"
#include "ethernet.h"

void parse_ethernet(packet *pkt, packet_info *pkt_info)
{
    ether_header *hdr = pkt->ether_hdr;

    uint8_t *curr = reinterpret_cast<uint8_t*>(hdr);

    QTreeWidgetItem *tree = ITEM("Ethernet Header");
    pkt_info->detail->addChild(tree);

    QString src_mac, dst_mac;
    dst_mac = toMAC(hdr->ether_dhost);
    tree->addChild(ITEM(QString("Destination"" --- %1").arg(dst_mac)));
    src_mac = toMAC(hdr->ether_shost);
    tree->addChild(ITEM(QString("Source"" --- %1").arg(src_mac)));

    switch (ntohs(hdr->ether_type)) {
    case ETHERTYPE_IP:
        tree->addChild((ITEM("Type --- IPv4")));
        pkt->ipv4_hdr = reinterpret_cast<ipv4_header*>(curr + ETHER_HDRLEN);
        break;
    case ETHERTYPE_IPV6:
        tree->addChild((ITEM("Type --- IPv6")));
        pkt->ipv6_hdr = reinterpret_cast<ipv6_header*>(curr + ETHER_HDRLEN);
        break;
    case ETHERTYPE_ARP:
        tree->addChild((ITEM("Type --- ARP")));
        pkt->arp_hdr = reinterpret_cast<arp_header*>(curr + ETHER_HDRLEN);;
        pkt_info->protocol = "ARP";
        pkt_info->src_addr = src_mac;
        pkt_info->dst_addr = dst_mac;
        break;
    default:
        tree->addChild((ITEM("Type --- Unknown")));
        break;
    }
    pkt->len -= ETHER_HDRLEN;
}

