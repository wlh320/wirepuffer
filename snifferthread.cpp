
#include <QDateTime>

#include "snifferthread.h"
#include "protocols/packet.h"
#include "protocols/parser.h"

SnifferThread::SnifferThread(char* dev, QStandardItemModel *pkt_model, QStatusBar *status_bar)
{
    this->pkt_model = pkt_model;
    this->status_bar = status_bar;

    this->dev = dev;
    this->is_stop = true;
    this->count = 0;
    // colors
    bgs.insert("ARP", QColor(250, 240, 215));
    bgs.insert("UDP", QColor(218, 238, 255));
    bgs.insert("TCP", QColor(231, 230, 255));
    bgs.insert("ICMP", QColor(252, 224, 255));
    bgs.insert("ICMPv6", QColor(252, 224, 255));
    bgs.insert("HTTP", QColor(228, 255, 199));
    bgs.insert("Unknown", QColor(255, 255, 255));
    bgs.insert("DNS", QColor(218, 238, 255));
    bgs.insert("HTTP", QColor(228, 255, 199));

//    fgs.insert("ICMP", QColor(72, 102, 63));
}
SnifferThread::~SnifferThread()
{

}

void SnifferThread::run()
{
    const char *filter_exp = this->filter.toStdString().c_str();
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_pkthdr *header;
    const u_char *data;
    bpf_u_int32 subnet_mask, ip;
    struct bpf_program filter;

    is_stop = false; // start
    // lookup device
    if (pcap_lookupnet(dev, &ip, &subnet_mask, errbuf) == -1) {
        status_bar->showMessage(QString("Can't get netmask for device %1, %2").arg(QString(dev)).arg(QString(errbuf)));
        ip = 0;
        subnet_mask = 0;
    }
    // open live
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        status_bar->showMessage(QString("Couldn't open device %1, %2").arg(QString(dev)).arg(QString(errbuf)));
        return ;
    }
    // set filter
    printf("%s\n", filter_exp);
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        status_bar->showMessage(QString("Bad filter - %1").arg(QString(pcap_geterr(handle))));
        this->filter = "";
        return ;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        status_bar->showMessage(QString("Error setting filter - %1").arg(QString(pcap_geterr(handle))));
        return ;
    }
    int ret = 0;
    // start capture
    while(!is_stop && (ret = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (ret == 1) {
            count++;

            uchar *tmp = new uchar[header->len];
            memcpy(tmp, data, header->len);
            pkts_raw.push_back(tmp);

            QList<QStandardItem *> row;
            row = handle_packet(header, data);

            // color
            QString protocol = row.at(4)->text();
            QColor bc = QColor(255, 255, 255);
            if (bgs.contains(protocol)) {
                bc = bgs.value(protocol);
            }
            QColor fc = QColor(0, 0, 0);
            if (fgs.contains(protocol)) {
                fc = fgs.value(protocol);
            }
            for (int i = 0; i < row.length(); ++i) {
                row.at(i)->setData(bc, Qt::BackgroundColorRole);
                row.at(i)->setData(fc, Qt::ForegroundRole);
            }

            pkt_model->appendRow(row);

        }
    }
    if (ret == PCAP_ERROR) {
        status_bar->showMessage(QString("Error while capturing"));
    }
    pcap_close(handle);
}

// handle packet
QList<QStandardItem *> SnifferThread::handle_packet(pcap_pkthdr *header, const uchar *data)
{

    QList<QStandardItem *> row;

    // frame number
    QStandardItem *numberItem = new QStandardItem();
    numberItem->setData(QVariant(count), Qt::DisplayRole);
    row.append(numberItem);

    // datetime
    QDateTime datetime = QDateTime::currentDateTime();
    row.append(new QStandardItem(datetime.toString("yyyy-M-d hh:mm:ss")));

    packet_info *pkt_info = parse(header->len, const_cast<uint8_t *>(data));

    //new QStandardItem("Src")
    row.append(new QStandardItem(pkt_info->src_addr));
    //new QStandardItem("Dest")
    row.append(new QStandardItem(pkt_info->dst_addr));
    //new QStandardItem("Protocol")
    row.append(new QStandardItem(pkt_info->protocol));
    //new QStandardItem("Len")
    row.append(new QStandardItem(QString::number(header->len)));
    //new QStandardItem("Info")
    row.append(new QStandardItem(pkt_info->info));

    delete pkt_info; // free
    return row;
}

void SnifferThread::stop()
{
    this->is_stop = true;
}

void SnifferThread::fill(int idx, int len, QTreeWidget *infoTreeWidget, QPlainTextEdit *rawTextEdit)
{
    // TODO maybe memory leak here
    infoTreeWidget->clear();
    rawTextEdit->clear();

    const uchar *data = pkts_raw[idx];
    packet_info *pkt_info = parse(static_cast<uint>(len), const_cast<uint8_t *>(data), true);

    QList<QTreeWidgetItem *> items;
    items.append(pkt_info->detail);

    infoTreeWidget->insertTopLevelItems(0, items);
    rawTextEdit->appendPlainText(pkt_info->rawhex);

    delete pkt_info;
}

void SnifferThread::clear()
{
    count = 0;
    pkts_raw.clear();
    pkt_model->clear();
    pkt_model->setHorizontalHeaderItem(0, new QStandardItem("#"));
    pkt_model->setHorizontalHeaderItem(1, new QStandardItem("Time"));
    pkt_model->setHorizontalHeaderItem(2, new QStandardItem("Src"));
    pkt_model->setHorizontalHeaderItem(3, new QStandardItem("Dest"));
    pkt_model->setHorizontalHeaderItem(4, new QStandardItem("Protocol"));
    pkt_model->setHorizontalHeaderItem(5, new QStandardItem("Len"));
    pkt_model->setHorizontalHeaderItem(6, new QStandardItem("Info"));
}

void SnifferThread::set_filter(QString filter)
{
    this->filter = filter;
}

QString SnifferThread::get_filter()
{
    return this->filter;
}
