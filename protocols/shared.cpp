#include <QStringList>
#include <QTreeWidgetItem>
#include <arpa/inet.h>
QTreeWidgetItem* ITEM(QString s)
{
    QTreeWidgetItem *item = new QTreeWidgetItem(QStringList(s));
    return item;
}

QString hexdump(uint len, uchar *raw, bool ascii)
{
    const uint COL = 8;
    uint row = (len + COL - 1) / COL;
    QString out;
    for (uint i = 0; i < row; i++) {
        for (uint j = 0; j < COL; j++) {
            uint idx = i * COL + j;
            if (idx < len) {
                out += QString("%1").arg(raw[idx], 2, 16, QChar('0')).toUpper();
            } else {
                out += "  ";
            }
            out += " ";
        }
        out += "  ";
        if (ascii) {
            for (uint j = 0; j < COL; j++) {
                uint idx = i * COL + j;
                if (idx >= len) {
                    break;
                }
                if (raw[idx] >= 32) {
                    out += QChar(raw[idx]);
                } else {
                    out += ".";
                }
            }
        }
        out += "\n";
    }
    return out;
}

QString toMAC(uint8_t *arr)
{
    char buffer[18];
    //Append the destination mac address
    snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X",
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]);

    return QString(buffer);
}

QString toIPv4(uint8_t *arr)
{
    char addr_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arr, addr_buf, sizeof(addr_buf));
    return QString(addr_buf);
}

QString toIPv6(uint8_t *arr)
{
    char addr_buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, arr, addr_buf, sizeof(addr_buf));
    return QString(addr_buf);
}

QString toBinary(uint8_t x)
{
    QString out;
    uint8_t mask = 0x80; // 1000 0000
    while(mask) {
        out += ((x & mask) ? '1': '0');
        mask >>= 1;
    }
    return out;
}
