#-------------------------------------------------
#
# Project created by QtCreator 2019-03-27T10:46:26
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = wirepuffer
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

LIBS += -lpcap
LIBS += -lglog

CONFIG += c++11

SOURCES += \
        main.cpp \
    mainwindow.cpp \
    snifferthread.cpp \
    protocols/parser.cpp \
    protocols/arp.cpp \
    protocols/ethernet.cpp \
    protocols/ipv4.cpp \
    protocols/ipv6.cpp \
    devdialog.cpp \
    protocols/shared.cpp \
    protocols/udp.cpp \
    protocols/tcp.cpp \
    protocols/icmpv4.cpp \
    protocols/icmpv6.cpp \
    protocols/dns.cpp

HEADERS += \
        mainwindow.h \
    snifferthread.h \
    protocols/ethernet.h \
    protocols/ipv4.h \
    protocols/ipv6.h \
    protocols/packet.h \
    protocols/parser.h \
    protocols/tcp.h \
    protocols/udp.h \
    protocols/arp.h \
    devdialog.h \
    protocols/shared.h \
    protocols/icmp.h \
    protocols/dns.h

FORMS += \
        mainwindow.ui \
    devdialog.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES +=

RESOURCES += \
    resources.qrc

