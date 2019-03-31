#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "devdialog.h"
#include "chartwindow.h"


#include <QInputDialog>
#include <QMessageBox>
#include <QFileDialog>
#include <QStandardPaths>
#include <QLineEdit>
#include <QDebug>
#include <QHash>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->actionStop->setDisabled(true);

    // set model and table
    pkt_model = new QStandardItemModel(0, 7, this);
    pkt_model->setHorizontalHeaderItem(0, new QStandardItem("#"));
    pkt_model->setHorizontalHeaderItem(1, new QStandardItem("Time"));
    pkt_model->setHorizontalHeaderItem(2, new QStandardItem("Src"));
    pkt_model->setHorizontalHeaderItem(3, new QStandardItem("Dest"));
    pkt_model->setHorizontalHeaderItem(4, new QStandardItem("Protocol"));
    pkt_model->setHorizontalHeaderItem(5, new QStandardItem("Len"));
    pkt_model->setHorizontalHeaderItem(6, new QStandardItem("Info"));

    ui->packetTableView->setModel(pkt_model);
    ui->packetTableView->resizeColumnsToContents();
    ui->packetTableView->verticalHeader()->setMaximumSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->setDefaultSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->hide();

    ui->packetTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    ui->packetInfoTree->setColumnCount(1);
    ui->packetInfoTree->setHeaderHidden(true);

    ui->mainToolBar->setIconSize(QSize(24, 24));
    ui->statusBar->setStyleSheet("color: #aa0000");
    // data
    this->dev = "";
    sniff_thread = new SnifferThread(pkt_model, ui->statusBar);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionStart_triggered()
{
    // choose device
    DevDialog d(nullptr);

    int code = d.exec();
    if (code != QDialog::Accepted) {
        return ;
    }
    if (this->dev == "") {
        QString chosen = d.getDev();
        sniff_thread->set_dev(chosen);
        this->dev = chosen;
    }
    sniff_thread->init(false, ""); // live capture
    sniff_thread->clear();
    sniff_thread->start();

    ui->actionStart->setDisabled(true);
    ui->actionStop->setDisabled(false);
}

void MainWindow::on_actionStop_triggered()
{
    sniff_thread->stop();
    ui->actionStop->setDisabled(true);
    ui->actionStart->setDisabled(false);
}

void MainWindow::on_actionClear_triggered()
{
    if (sniff_thread != nullptr) {
        sniff_thread->clear();
        ui->packetInfoTree->clear();
        ui->packetRawTextEdit->clear();
    }
}

void MainWindow::on_packetTableView_clicked(const QModelIndex &index)
{
    if (sniff_thread != nullptr) {
        int idx = pkt_model->data(pkt_model->index(index.row(), 0)).toInt();
        int len = pkt_model->data(pkt_model->index(index.row(), 5)).toInt();

        sniff_thread->fill(idx - 1, len, ui->packetInfoTree, ui->packetRawTextEdit);

        ui->packetInfoTree->expandToDepth(0);
    }
}

void MainWindow::on_actionactionFitTable_triggered()
{
    ui->packetTableView->resizeColumnsToContents();
}

void MainWindow::on_actionactionSetFilter_triggered()
{
    bool ok;
    QString text = QInputDialog::getText(this, tr("filter"),
                                        tr("Set filter:"), QLineEdit::Normal, "", &ok);
    if (ok) {
        if (sniff_thread) {
            sniff_thread->set_filter(text);
            ui->statusBar->showMessage("Set filter to '"  + text + "'");
        }
    }
}

void MainWindow::on_actionactionStatistic_triggered()
{
    if (pkt_model->rowCount() > 0) {
        QHash<QString, int> stat = sniff_thread->get_dns_stat();
        ChartWindow *w = new ChartWindow(stat, this);
        w->show();
    } else {
        QMessageBox::warning(this, "No capture", "No capture data");
    }
}

void MainWindow::on_actionOpen_triggered()
{
    QString txt = QFileDialog::getOpenFileName(this, "Open File", QStandardPaths::displayName(QStandardPaths::DesktopLocation),
    "pcap File(*.pcap);; All files(*.*)");
    // click cancel
    if(txt.length() == 0){
        ui->statusBar->showMessage("No file selected.");
        return;
    }

    char *filename = new char[txt.length()];
    strcpy(filename, txt.toStdString().c_str());
    sniff_thread->init(true, filename);
    delete[] filename;

    ui->actionClear->setDisabled(true);
    sniff_thread->start();
}

void MainWindow::on_actionSave_triggered()
{
    QString filepath = QFileDialog::getSaveFileName(this, "Open File", QStandardPaths::displayName(QStandardPaths::DesktopLocation),
    "pcap File(*.pcap);; All files(*.*)");
    // click cancel
    if(filepath.length() == 0){
        ui->statusBar->showMessage("No file selected.");
        return;
    }

    if (sniff_thread) {
        sniff_thread->save(filepath);
    }
}
