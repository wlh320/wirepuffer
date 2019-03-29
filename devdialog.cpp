#include "devdialog.h"
#include "ui_devdialog.h"
#include <pcap/pcap.h>
DevDialog::DevDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DevDialog)
{
    ui->setupUi(this);

    this->dev = "";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs;
    int err;
    err = pcap_findalldevs(&devs, errbuf);
    if (err == PCAP_ERROR) {
        fprintf(stderr, "%s\n", errbuf);
    }
    for (pcap_if_t *p = devs; p ; p = p->next) {
        ui->devCombo->addItem(QString(p->name));
    }
}

DevDialog::~DevDialog()
{
    delete ui;
}

QString DevDialog::getDev()
{
    return this->dev;
}

void DevDialog::on_DevDialog_accepted()
{
    this->dev = ui->devCombo->currentText();
    this->setResult(QDialog::Accepted);
    this->close();
}

void DevDialog::on_DevDialog_rejected()
{
    this->setResult(QDialog::Rejected);
    this->close();
}
