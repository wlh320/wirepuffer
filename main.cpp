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

    MainWindow w;
    w.show();

    return a.exec();
}
