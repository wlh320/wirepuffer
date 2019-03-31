#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include <QHash>
#include <QThread>
#include <QStandardItemModel>
#include <QTreeWidget>
#include <QStatusBar>
#include <QPlainTextEdit>
#include <pcap/pcap.h>

class SnifferThread : public QThread
{
private:
    // ui
    QStatusBar *status_bar;
    QStandardItemModel *pkt_model;
    QPlainTextEdit *pkt_info_text;
    QPlainTextEdit *pkt_raw_text;

    // data
    QList<const uchar*> pkts_raw;
    int count; // count of packet
    char *dev; // device name
    QString filter; // capture filter
    bool is_stop; // stop sign
    QHash<QString, QColor> bgs;
    QHash<QString, QColor> fgs;
    QList<QStandardItem *> handle_packet(pcap_pkthdr *header, const uchar *data);
    QHash<QString, int> dns_stat;

public:
    SnifferThread(char* dev, QStandardItemModel *pkt_model,  QStatusBar *status_bar);
    ~SnifferThread();

    void run();  // start packet sniffer
    void stop(); // stop packet sniffer
    void fill(int idx, int len, QTreeWidget *infoTreeWidget, QPlainTextEdit *rawTextEdit); // fill data into UI
    void clear(); // clear current packets
    void set_filter(QString);
    QString get_filter();
    QHash<QString, int> get_dns_stat();
};

#endif // SNIFFERTHREAD_H
