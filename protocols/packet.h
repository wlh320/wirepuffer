#ifndef __PACKET_H__
#define __PACKET_H__

#include <QString>
#include <QTreeWidgetItem>

struct ether_header;
struct arp_header;
struct ipv4_header;
struct ipv6_header;
struct tcp_header;
struct udp_header;
struct icmpv4_header;
struct icmpv6_header;
// readable packet info
// parsing result
struct packet
{
    int32_t len;
    // layer 2
    ether_header *ether_hdr = nullptr;

    // layer 3
    ipv4_header *ipv4_hdr = nullptr;
    ipv6_header *ipv6_hdr = nullptr;
    arp_header *arp_hdr = nullptr;

    // layer 4
    tcp_header *tcp_hdr = nullptr;
    udp_header *udp_hdr = nullptr;
    icmpv4_header *icmpv4_hdr = nullptr;
    icmpv6_header *icmpv6_hdr = nullptr;

    // layer 5
    uint8_t *app_payload = nullptr;
};

// readable packet info
struct packet_info
{
    // general info
    QString src_addr = "Unknown";
    QString dst_addr = "Unknown";
    QString protocol = "Unknown";
    QString len = "Unknown";
    QString info = "Unknown";


//    QString detail = "";
    // detail info
    QTreeWidgetItem *detail;
    // current tree node
    QString rawhex = "";
};

#endif
