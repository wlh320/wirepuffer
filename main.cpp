#include "mainwindow.h"
#include "devdialog.h"
#include <QApplication>
#include <glog/logging.h>

int main(int argc, char *argv[])
{
    // logging
    google::InitGoogleLogging(argv[0]);
    // hidpi support
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    // qt
    QApplication a(argc, argv);
    a.setWindowIcon(QIcon(":/icons/wirepuffer.png"));

    DevDialog d(nullptr);

    int code = d.exec();
    if (code == QDialog::Accepted) {
        MainWindow w(nullptr, d.getDev());
        w.show();
        a.exec();
    }
//    return a.exec();
    return 0;
}
