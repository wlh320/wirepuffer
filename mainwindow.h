#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItem>
#include "snifferthread.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr, QString dev = "");
    ~MainWindow();

private slots:
    void on_actionStart_triggered();

    void on_actionStop_triggered();

    void on_actionClear_triggered();

    void on_packetTableView_clicked(const QModelIndex &index);

    void on_actionactionFitTable_triggered();

    void on_actionactionSetFilter_triggered();

private:
    Ui::MainWindow *ui;

    // data
    char *dev;
    SnifferThread *sniff_thread;
    QStandardItemModel *pkt_model;
};

#endif // MAINWINDOW_H
