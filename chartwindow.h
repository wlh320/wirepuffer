#ifndef CHARTWINDOW_H
#define CHARTWINDOW_H

#include <QMainWindow>

#include <QtCharts/QChartView>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QHash>

QT_CHARTS_USE_NAMESPACE

class ChartWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit ChartWindow(QHash<QString, int> &dns_stat, QWidget *parent = nullptr);
    ~ChartWindow();
signals:

public slots:

private:
    QPieSeries *series;
    QChart *chart;
    QChartView *chartView;
};

#endif // CHARTWINDOW_H
