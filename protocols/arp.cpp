#include <cstdio>
#include <arpa/inet.h>
#include "shared.h"
#include "arp.h"
static const char *opcodeStrings[] =
{
    "ARP REQUEST",
    "ARP REPLY",
    "RARP REQUEST",
    "RARP RAPLY",
    "DRARP REQUEST",
    "DRARP REPLY",
    "DRARP ERROR",
    "INARP REQUEST",
    "INARP REPLY"
};

void parse_arp(packet *pkt, packet_info *pkt_info)
{
    arp_header *hdr = pkt->arp_hdr;

    QTreeWidgetItem *tree = ITEM("Address Resolution Protocol");
    pkt_info->detail->addChild(tree);

    uint16_t hardware = ntohs(hdr->hardware);
    uint16_t protocol = ntohs(hdr->protocol);
    uint16_t opcode = ntohs(hdr->opcode);

    // opcode
    if(opcode >= 1 && opcode <= 9) {
        tree->addChild(ITEM(QString( "Operation" " ---- %1 (%2)").arg(opcode).arg(opcodeStrings[opcode-1])));
    } else {
        tree->addChild(ITEM(QString( "Operation" " ---- Not Implemented")));
        return;
    }

    // hardware
    switch(hardware) {
    case ARP_HARDWARE_TYPE_ETHERNET:
        tree->addChild(ITEM(QString( "Hardware"  " ----- %1 (Ethernet)").arg(hardware)));
        break;
    default:
        tree->addChild(ITEM(QString( "Hardware" " ---- Not Implemented")));
        return;
    }

    // protocol
    switch(protocol) {
    case ARP_PROTOCOL_TYPE_IPV4:
        tree->addChild(ITEM( "Protocol" " ----- IPv4"));
        break;
    default:
        tree->addChild(ITEM( "Protocol" " Not implemented"));
        return;
    }

    tree->addChild(ITEM(QString("Hardware len" " - %1").arg(hdr->hlen)));
    tree->addChild(ITEM(QString("Protocol len" " - %1").arg(hdr->plen)));

    uint8_t *data = reinterpret_cast<uint8_t *>(hdr) + 8;
    uint8_t *sender_hardware = data;
    uint8_t *sender_ip = data;
    uint8_t *dest_hardware = data;
    uint8_t *dest_ip = data;

    QString sender_mac_str = toMAC(sender_hardware);

    switch(hdr->hlen) {
    case ARP_MAC_LENGTH:
        tree->addChild(ITEM(QString( "Sender. MAC" " --- %1").arg(sender_mac_str)));
        sender_ip += ARP_MAC_LENGTH;
        break;

    default:
        tree->addChild(ITEM("Hardware Len Not implemented"));
        return;
    }
    QString sender_ip_str, dest_ip_str, dest_mac_str, info;
    switch(hdr->plen) {
    case ARP_IPv4_LENGTH:

        sender_ip_str = toIPv4(sender_ip);
        tree->addChild(ITEM(QString("Sender. IP" " ---- %1").arg(sender_ip_str)));

        dest_hardware += hdr->hlen + ARP_IPv4_LENGTH;
        dest_ip += hdr->hlen + ARP_IPv4_LENGTH + hdr->hlen;

        dest_mac_str = toMAC(dest_hardware);
        tree->addChild(ITEM(QString( "Dest. MAC" " ---- %1").arg(dest_mac_str)));

        dest_ip_str = toIPv4(dest_ip);
        tree->addChild(ITEM(QString("Dest. IP" " ----- %1").arg(dest_ip_str)));

        if(opcode == ARP_OPCODE_REQUEST){
            info = QString("Who has %1, tell %2").arg(dest_ip_str).arg(sender_ip_str);
        }
        else if(opcode == ARP_OPCODE_REPLY){
            info = QString("%1 is at %2").arg(QString(sender_ip_str)).arg(sender_mac_str);
        }
        break;
    default:
        tree->addChild(ITEM("Network length not implement"));
        return;
    }
    pkt_info->info = info;

}
