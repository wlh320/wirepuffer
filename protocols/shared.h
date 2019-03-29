#ifndef TAGS_H
#define TAGS_H

#include <QStringList>
#include <QTreeWidgetItem>

// helper

QTreeWidgetItem* ITEM(QString s);
QString hexdump(uint len, uchar *raw, bool ascii = true);
QString toMAC(uint8_t *arr);
QString toIPv4(uint8_t *arr);
QString toIPv6(uint8_t *arr);
QString toBinary(uint8_t x);
#endif // TAGS_H
