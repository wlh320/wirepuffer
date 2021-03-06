
#include <QDateTime>

#include "snifferthread.h"
#include "protocols/packet.h"
#include "protocols/parser.h"

SnifferThread::SnifferThread(QStandardItemModel *pkt_model, QStatusBar *status_bar)
{
    this->pkt_model = pkt_model;
    this->status_bar = status_bar;

    this->is_stop = true;
    this->count = 0;

    this->dev = new char[1024];
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
}
SnifferThread::~SnifferThread()
{
    // TODO release memory allocated
    delete this->dev;
    pcap_close(handle);
}

void SnifferThread::init(bool is_open, QString filename)
{
    const char *filter_exp = this->filter.toStdString().c_str();
    bpf_program filter;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnet_mask, ip;

    // lookup device
    if (pcap_lookupnet(this->dev, &ip, &subnet_mask, errbuf) == -1) {
        status_bar->showMessage(QString("Can't get netmask for device %1, %2").arg(QString(dev)).arg(QString(errbuf)));
        ip = 0;
        subnet_mask = 0;
    }
    if (is_open) { // open file
        handle = pcap_open_offline(filename.toStdString().c_str(), errbuf);
        if (handle == nullptr) {
            status_bar->showMessage(QString("Couldn't open file %1, %2").arg(QString(filename)).arg(QString(errbuf)));
            return ;
        }
    } else { // open live
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            status_bar->showMessage(QString("Couldn't open device %1, %2").arg(QString(dev)).arg(QString(errbuf)));
            return ;
        }
    }
    // set filter
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        status_bar->showMessage(QString("Bad filter - %1").arg(QString(pcap_geterr(handle))));
        this->filter = "";
        return ;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        status_bar->showMessage(QString("Error setting filter - %1").arg(QString(pcap_geterr(handle))));
        return ;
    }
}

void SnifferThread::run()
{
    if (!handle) {
        return ;
    }
    QString f = this->filter.length() == 0? "None" : this->filter;
    status_bar->showMessage(QString("Capture Started. Interface: ") + QString(dev) + " Filter: " + f);

    pcap_pkthdr *header;
    const u_char *data;
    is_stop = false; // start
    int ret = 0;
    // start capture
    while(!is_stop && (ret = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (ret == 1) {
            count++;
            cache_packet(header, data);
            QList<QStandardItem *> row;
            row = handle_packet(header, data);
            pkt_model->appendRow(row);
        }
    }
    // stopped
    status_bar->showMessage("Capture Stopped. Filter: " + f);
    if (ret == PCAP_ERROR) {
        status_bar->showMessage(QString("Error while capturing"));
    }
}

void SnifferThread::cache_packet(pcap_pkthdr *header, const uchar *data)
{
    pcap_pkthdr *tmp_hdr = new pcap_pkthdr;
    memcpy(tmp_hdr, header, sizeof(pcap_pkthdr));
    pkts_hdr.push_back(tmp_hdr);

    uchar *tmp = new uchar[header->len];
    memcpy(tmp, data, header->len);
    pkts_raw.push_back(tmp);

}

// parse packet
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


    QString prot = pkt_info->protocol;
    QString info = pkt_info->info;
    // color
    QColor bc = bgs.contains(prot)? bgs.value(prot): QColor(255, 255, 255);
    QColor fc = fgs.contains(prot)? fgs.value(prot): QColor(0, 0, 0);
    for (int i = 0; i < row.length(); ++i) {
        row.at(i)->setData(bc, Qt::BackgroundColorRole);
        row.at(i)->setData(fc, Qt::ForegroundRole);
    }
    // DNS statistics 赶时间写的狗屎代码
    if (prot == "DNS") { // stat
        // info example : Standard query 0xFFFF A g.cn
        QStringList infos = info.split(" ");
        if (infos.at(2) == "response") {
            QString name = infos.at(5);
            if (dns_stat.contains(name)){
                dns_stat[name]++;
            } else {
                dns_stat[name] = 1;
            }
        }
    }
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
    pkts_hdr.clear();
    pkt_model->clear();
    pkt_model->setHorizontalHeaderItem(0, new QStandardItem("#"));
    pkt_model->setHorizontalHeaderItem(1, new QStandardItem("Time"));
    pkt_model->setHorizontalHeaderItem(2, new QStandardItem("Src"));
    pkt_model->setHorizontalHeaderItem(3, new QStandardItem("Dest"));
    pkt_model->setHorizontalHeaderItem(4, new QStandardItem("Protocol"));
    pkt_model->setHorizontalHeaderItem(5, new QStandardItem("Len"));
    pkt_model->setHorizontalHeaderItem(6, new QStandardItem("Info"));
}

void SnifferThread::set_dev(QString devname)
{
    strcpy(dev, devname.toStdString().c_str());
}

void SnifferThread::set_filter(QString filter)
{
    this->filter = filter;
}

QHash<QString, int> SnifferThread::get_dns_stat()
{
    return this->dns_stat;
}

void SnifferThread::save(QString filepath)
{
    pcap_dumper_t *dumper = nullptr;
    dumper = pcap_dump_open(handle, filepath.toStdString().c_str());
    if (!dumper) {
        status_bar->showMessage("Error: " + QString(pcap_geterr(handle)));
        return ;
    }
    for (int i = 0; i < pkts_hdr.count(); i++) {
        pcap_dump(reinterpret_cast<uchar*>(dumper), pkts_hdr[i], pkts_raw[i]);
    }
    status_bar->showMessage("Saved to " + QString(filepath));
}
