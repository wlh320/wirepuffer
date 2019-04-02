#include "shared.h"
#include "icmp.h"
#include <arpa/inet.h>
void parse_icmpv4(packet *pkt, packet_info *pkt_info)
{
    icmpv4_header *hdr = pkt->icmpv4_hdr;

    uint8_t type = hdr->type;
    uint8_t code = hdr->code;
    uint16_t checksum = ntohs(hdr->checksum);

    QTreeWidgetItem *tree = ITEM("Internet Control Message Protocol v4");
    QString type_str = QString("[%2](%1)").arg(type);
    switch (type) {
    case ICMP_TYPE_ECHO_REPLY:
        type_str = type_str.arg("Echo Reply");
        break;
    case ICMP_TYPE_ECHO_REQUEST:
        type_str = type_str.arg("Echo (ping) Request");
        break;
    case ICMP_TYPE_DEST_UNREACH:
        type_str = type_str.arg("Destination Unreachable");
        break;
    default:
        type_str = type_str.arg("Not Implemented");
        break;
    }
    pkt_info->info = type_str;
    tree->addChild(ITEM(QString("Type --------- " + type_str)));
    pkt_info->detail->addChild(tree);
    tree->addChild(ITEM(QString("Code --------- %1").arg(code)));
    char tmp[256];
    sprintf(tmp, "Checksum ----- 0x%04X", checksum);
    tree->addChild(ITEM(tmp));

    QTreeWidgetItem *data = ITEM("Data");
    tree->addChild(data);

    uint offset = 3;
    uint8_t* addr = reinterpret_cast<uint8_t*>(hdr) + offset;
    QString data_str = hexdump(pkt->len - offset, addr, false);

    data->addChild(ITEM(data_str));
}
