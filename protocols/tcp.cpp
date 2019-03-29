#include "shared.h"
#include "tcp.h"
#include <arpa/inet.h>

void parse_tcp(packet *pkt, packet_info *pkt_info)
{
    tcp_header *hdr = pkt->tcp_hdr;
    uint8_t *curr = reinterpret_cast<uint8_t*>(hdr);

    uint16_t src_port = ntohs(hdr->src_port);
    uint16_t dst_port = ntohs(hdr->dst_port);
    uint32_t seq_num  = ntohl(hdr->seq);
    uint32_t ack_num  = ntohl(hdr->ack_seq);
    uint16_t window   = ntohs(hdr->window);
    uint16_t checksum = ntohs(hdr->checksum);
    int hdr_len = hdr->doff << 2;

    QString info = QString("%1 -> %2").arg(src_port).arg(dst_port);

    QTreeWidgetItem *tree = ITEM("Transmisson Control Protocol");
    pkt_info->detail->addChild(tree);

    tree->addChild(ITEM(QString("Src. port ---- %1").arg(src_port)));
    tree->addChild(ITEM(QString("Dst. port ---- %1").arg(dst_port)));
    tree->addChild(ITEM(QString("seq number --- %1").arg(seq_num)));
    tree->addChild(ITEM(QString("ack number --- %1").arg(ack_num)));
    tree->addChild(ITEM(QString("header len --- %1 bytes").arg(hdr_len)));

    QTreeWidgetItem *flags = ITEM("FLAGS");
    tree->addChild(flags);
    flags->addChild(ITEM(QString("CWR %1.......").arg(hdr->cwr)));
    flags->addChild(ITEM(QString("ECE .%1......").arg(hdr->ece)));
    flags->addChild(ITEM(QString("URG ..%1.....").arg(hdr->urg)));
    flags->addChild(ITEM(QString("ACK ...%1....").arg(hdr->ack)));
    flags->addChild(ITEM(QString("PSH ....%1...").arg(hdr->psh)));
    flags->addChild(ITEM(QString("RST .....%1..").arg(hdr->rst)));
    flags->addChild(ITEM(QString("SYN ......%1.").arg(hdr->syn)));
    flags->addChild(ITEM(QString("FIN .......%1").arg(hdr->fin)));

    tree->addChild(ITEM(QString("window     --- %1").arg(window)));
    char tmp[256];
    sprintf(tmp, "Checksum ----- 0x%04X", checksum);
    tree->addChild(ITEM(tmp));

    // append info
    if (hdr->ack) {
        info += " [ACK]";
    }
    if (hdr->rst) {
        info += " [RST]";
    }
    if (hdr->syn) {
        info += " [SYN]";
    }
    if (hdr->fin) {
        info += " [FIN]";
    }
    pkt_info->info = info;
    pkt->len -= hdr_len;
    // next layer
    // TODO
    curr += hdr_len;
}
