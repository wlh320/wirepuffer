#ifndef __WTF_H__
#define __WTF_H__
#include <cstdint>
#include "packet.h"
#include <pcap/pcap.h>

packet_info* parse(uint len, uchar *raw, bool is_full = false);

#endif
