#ifndef DEVDIALOG_H
#define DEVDIALOG_H

#include <QDialog>
#include <QButtonGroup>
#include <QString>

namespace Ui {
class DevDialog;
}

class DevDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DevDialog(QWidget *parent = nullptr);
    ~DevDialog();
    QString getDev();

private slots:

    void on_DevDialog_accepted();

    void on_DevDialog_rejected();

private:
    Ui::DevDialog *ui;
    QString dev;
};

#endif // DEVDIALOG_H
