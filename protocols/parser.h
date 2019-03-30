#ifndef PARSER_H
#define PARSER_H
#include <cstdint>
#include "packet.h"
#include <pcap/pcap.h>

packet_info* parse(uint len, uchar *raw, bool is_full = false);

#endif
