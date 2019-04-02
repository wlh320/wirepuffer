#include "shared.h"
#include "udp.h"

#include "dns.h"
#include <arpa/inet.h>

void parse_udp(packet *pkt, packet_info *pkt_info)
{
    udp_header *hdr = pkt->udp_hdr;
    uint8_t *curr = reinterpret_cast<uint8_t*>(hdr);

    uint16_t src_port = ntohs(hdr->src_port);
    uint16_t dst_port = ntohs(hdr->dst_port);
    uint16_t checksum = ntohs(hdr->checksum);
    uint16_t length   = ntohs(hdr->len);

    QString info = QString("%1 -> %2 Len=%3").arg(src_port).arg(dst_port).arg(length);
    pkt_info->info = info;

    QTreeWidgetItem *tree = ITEM("User Datagram Protocol");
    pkt_info->detail->addChild(tree);

    tree->addChild(ITEM(QString("Src. port ---- %1").arg(src_port)));
    tree->addChild(ITEM(QString("Dst. port ---- %1").arg(dst_port)));
    tree->addChild(ITEM(QString("Length ------- %1").arg(length)));
    char tmp[256];
    sprintf(tmp, "Checksum ----- 0x%04X", checksum);
    tree->addChild(ITEM(tmp));

    pkt->len -= length;
    // next layer
    // TODO
    if (src_port == DNS_PORT || dst_port == DNS_PORT) {
        pkt->dns_hdr = reinterpret_cast<dns_header*>(curr + sizeof (udp_header));
        pkt_info->protocol = "DNS";
    }
}
