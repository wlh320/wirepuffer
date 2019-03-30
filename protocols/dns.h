#ifndef DNS_H
#define DNS_H

#include <cstdint>
#include <endian.h>
//0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                      ID                       |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|QR|   Opcode  |AA|TC|RD|RA|    Z   |   RCODE   |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    QDCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    ANCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    NSCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    ARCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

struct dns_header
{
    // little endian
    uint16_t trans_id;

    uint16_t rd:1;  /* recursion resired */
    uint16_t tc:1;  /* truncated */
    uint16_t aa:1;  /* authoriative */
    uint16_t opcode:4; /* op code */
    uint16_t qr:1;  /* response */
    uint16_t rcode:4; /* reply code */
    uint16_t zero:3; /* zero */
    uint16_t ra:1;   /* recursion avaiable */

    uint16_t qdcount;	/* Question count */
    uint16_t ancount;	/* Answer record count */
    uint16_t nscount;	/* Name Server (Autority Record) Count */
    uint16_t adcount;	/* Additional Record Count */
};

#define DNS_PORT 53

#define DNS_OPCODE_QUERY              0
#define DNS_OPCODE_IQUERY             1
#define DNS_OPCODE_STATUS             2
#define DNS_OPCODE_RESERVED           3
#define DNS_OPCODE_NOTIFY             4
#define DNS_OPCODE_UPDATE             5

/* RFC 1035 */
#define DNS_RCODE_NO_ERR              0
#define DNS_RCODE_FMT_ERR             1
#define DNS_RCODE_SERV_ERR            2
#define DNS_RCODE_NAME_ERR            3
#define DNS_RCODE_NOT_IMPL            4
#define DNS_RCODE_REFUSED             5
#define DNS_RCODE_YX_DOMAIN           6
#define DNS_RCODE_YX_RR_SET           7
#define DNS_RCODE_NX_RR_SET           8
#define DNS_RCODE_NOT_AUTH            9
#define DNS_RCODE_NOTZONE             10

#define DNS_RECORD_A                  1
#define DNS_RECORD_AAAA               28
#define DNS_RECORD_CNAME              5

#define DNS_CLASS_IN                 1

#define DNS_IS_POINTER(name)   (((name) & 0xC000) == 0xC000 ? 1 : 0)
#define DNS_NAME_OFFSET(ptr)    (((ptr) & 0x3FFF))

#include "packet.h"
void parse_dns(packet *pkt, packet_info *pkt_info);

#endif // DNS_H
