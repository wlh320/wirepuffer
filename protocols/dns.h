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

    uint16_t qdcount;	/* question count */
    uint16_t ancount;	/* Answer record count */
    uint16_t nscount;	/* Name Server (Autority Record) Count */
    uint16_t adcount;	/* Additional Record Count */
};

#define DNS_PORT 53

#include "packet.h"
void parse_dns(packet *pkt, packet_info *pkt_info);

#endif // DNS_H
