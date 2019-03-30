#include <cstdio>
#include <arpa/inet.h>
#include "shared.h"
#include "dns.h"

uint8_t* read_uint16(uint8_t* addr, uint16_t* ans)
{
    *ans = ntohs(*reinterpret_cast<uint16_t*>(addr));
    return addr + 2;
}

uint8_t* read_uint32(uint8_t* addr, uint32_t* ans)
{
    *ans = ntohl(*reinterpret_cast<uint32_t*>(addr));
    return addr + 4;
}

// parse domain name to domain and return end address
uint8_t* parse_name(uint8_t* data, QString &name)
{
    while (*data < 32) { // skip non-ascii
        data++;
    }
    while (*data) {
        if (*data >= 32) {
            name += QChar(*data);
        } else {
            name += '.';
        }
        data++;
    }
    return (data + 1);
}

QString dns_type_str(int type)
{
    switch (type) {
    case DNS_RECORD_A: return "A";
    case DNS_RECORD_CNAME: return "CNAME";
    case DNS_RECORD_AAAA: return "AAAA";
    default: return "Unknown";
    }
}
QString dns_class_str(int cls)
{
    switch (cls) {
    case DNS_CLASS_IN: return "IN";
    default: return "Unknown";
    }
}

void parse_rr_name(dns_header *hdr, uint16_t ptr, QString &name)
{
    uint8_t* data = reinterpret_cast<uint8_t*>(hdr);
    if (DNS_IS_POINTER(ptr)) {
        data += DNS_NAME_OFFSET(ptr);
    }
    while (*data) {
        read_uint16(data, &ptr);
        if (DNS_IS_POINTER(ptr)) {
            data += DNS_NAME_OFFSET(ptr);
        } else {
            if (*data >= 32) {
                name += QChar(*data);
            } else {
                name += '.';
            }
        }
        data++;
    }
}

// parse answers, authoritys and additional
void parse_rr_set(QString setname, int count, dns_header *hdr, uint8_t* curr, QTreeWidgetItem *tree)
{
    if (count <= 0) return ;
    QTreeWidgetItem *set = ITEM(setname);
    tree->addChild(set);
    for (int i = 0; i < count; i++) {
        uint16_t ptr, type, cls, len;
        uint32_t ttl;
        curr = read_uint16(curr, &ptr);
        curr = read_uint16(curr, &type);
        curr = read_uint16(curr, &cls);
        curr = read_uint32(curr, &ttl);
        curr = read_uint16(curr, &len);
        QString name;
        parse_rr_name(hdr, ptr, name);
        QString info = "%1 Type %2, Class %3, %4";
        info = info.arg(name).arg(dns_type_str(type)).arg(dns_class_str(cls));
        QString ans = "";
        switch (type) {
        case DNS_RECORD_A:
            if (len == 4) {
                ans = toIPv4(curr);
            }
            break;
        case DNS_RECORD_AAAA:
            if (len == 16) {
                ans = toIPv6(curr);
            }
            break;
        case DNS_RECORD_CNAME:
            for (int i = 0; i < len - 2; i++) {
                ans += (curr[i] < 32 ? '.' : QChar(curr[i]));
            }
            read_uint16(curr + len - 2, &ptr);
            parse_rr_name(hdr, ptr, ans);
            break;
        default:
            ans = "Unknown";
            break;
        }
        info = info.arg(ans);
        QTreeWidgetItem *set_item = ITEM(info);
        set_item->addChild(ITEM(QString("Type %1").arg(type)));
        set_item->addChild(ITEM(QString("TTL %1").arg(ttl)));
        set_item->addChild(ITEM(QString("Data length %1").arg(len)));
        set_item->addChild(ITEM(QString("Address %1").arg(ans)));
        set->addChild(set_item);
        curr += len;
    }
}

void parse_dns(packet *pkt, packet_info *pkt_info)
{
    dns_header *hdr = pkt->dns_hdr;
    QTreeWidgetItem *tree = ITEM("Domain Name System");
    pkt_info->detail->addChild(tree);

    uint16_t trans_id = ntohs(hdr->trans_id);
    uint16_t qdcount  = ntohs(hdr->qdcount);
    uint16_t ancount  = ntohs(hdr->ancount);
    uint16_t nscount  = ntohs(hdr->nscount);
    uint16_t adcount  = ntohs(hdr->adcount);

    char tmp[256];
    sprintf(tmp, "Transaction id ---- 0x%04X", trans_id);
    tree->addChild(ITEM(tmp));
    // flags
    // TODO
    tree->addChild(ITEM(QString("Questions  ---- %1").arg(qdcount)));
    tree->addChild(ITEM(QString("Answer RRs ---- %1").arg(ancount)));
    tree->addChild(ITEM(QString("Authority RRs ---- %1").arg(nscount)));
    tree->addChild(ITEM(QString("Additional RRs ---- %1").arg(adcount)));
    // opcode
    switch (hdr->opcode) {
    case DNS_OPCODE_QUERY:
        pkt_info->info = "Standard query ";
        break;
    default:
        pkt_info->info = "Not Implemented query ";
        break;
    }
    if (hdr->qr == 1) {
        pkt_info->info += "response ";
    }
    sprintf(tmp, "0x%04X ", trans_id);
    pkt_info->info += tmp;

    uint8_t *curr = reinterpret_cast<uint8_t*>(hdr) + sizeof(dns_header);
    // parse queries
    QTreeWidgetItem *queries = ITEM("Queries");
    tree->addChild(queries);
    for (int i = 0; i < qdcount; i++) {
        QString name = "";
        curr = parse_name(curr, name);
        uint16_t type, cls;
        curr = read_uint16(curr, &type);
        curr = read_uint16(curr, &cls);
        QString info = QString("%1 type: %2 class: %3").arg(name).
                                arg(dns_type_str(type)).arg(dns_class_str(cls));
        queries->addChild(ITEM(info));
        pkt_info->info += QString("%1 %2").arg(dns_type_str(type)).arg(name);
    }
    if (hdr->qr == 0) { // no response
        return ;
    }
    // parse answers
    parse_rr_set("Answers", ancount, hdr, curr, tree);
    // parse authority
    parse_rr_set("Authority", nscount, hdr, curr, tree);
    // parse additional
    parse_rr_set("Additional", adcount, hdr, curr, tree);
}
