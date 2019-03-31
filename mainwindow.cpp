#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "chartwindow.h"

#include <QInputDialog>
#include <QMessageBox>
#include <QLineEdit>
#include <QDebug>
#include <QHash>


MainWindow::MainWindow(QWidget *parent, QString dev) :
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
    this->dev = nullptr;
    this->dev = new char[256];
    strcpy(this->dev, dev.toStdString().c_str());
    ui->statusBar->showMessage("current interface: " + QString(this->dev));

//    ui->mainSplitter->setStretchFactor(0, 1);
//    ui->mainSplitter->setStretchFactor(1, 0);

    sniff_thread = nullptr;
    sniff_thread = new SnifferThread(this->dev, pkt_model, ui->statusBar);
}

MainWindow::~MainWindow()
{
    if (this->dev) {
        delete [] this->dev;
    }
    delete ui;
}

void MainWindow::on_actionStart_triggered()
{

    if (sniff_thread == nullptr) {
        sniff_thread = new SnifferThread(dev, pkt_model, ui->statusBar);
    }
    sniff_thread->start();
    ui->actionStart->setDisabled(true);
    ui->actionStop->setDisabled(false);
    QString f = sniff_thread->get_filter();
    if (f.length() == 0) {
        f = "None";
    }
    ui->statusBar->showMessage("Capture Started. Filter: " + f);
}

void MainWindow::on_actionStop_triggered()
{
    sniff_thread->stop();
    ui->actionStop->setDisabled(true);
    ui->actionStart->setDisabled(false);
    QString f = sniff_thread->get_filter();
    if (f.length() == 0) {
        f = "None";
    }
    ui->statusBar->showMessage("Capture Stopped. Filter: " + f);
}

void MainWindow::on_actionClear_triggered()
{
    if (sniff_thread != nullptr) {
        sniff_thread->clear();
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
