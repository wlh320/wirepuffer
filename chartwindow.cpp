#include "chartwindow.h"
#include <QMessageBox>
ChartWindow::ChartWindow(QHash<QString, int> &dns_stat, QWidget *parent) : QMainWindow(parent)
{
    QPieSeries *series = new QPieSeries();
    for (auto it = dns_stat.begin(); it != dns_stat.end(); it++) {
        series->append(it.key(), it.value());
    }

    for (int i = 0; i < series->slices().count(); ++i) {
        QPieSlice *slice = series->slices().at(i);
        slice->setLabel(QString("%1 %2%").arg(slice->label()).arg(100*slice->percentage(), 0, 'f', 1));
        slice->setLabelVisible();
    }

    chart = new QChart();
    chart->addSeries(series);
    chart->legend()->hide();

    chartView = new QChartView(chart);
    chartView->setRenderHint(QPainter::Antialiasing);

    this->setWindowTitle("DNS query statistics");
    this->setCentralWidget(chartView);
    this->resize(800, 600);
}

ChartWindow::~ChartWindow()
{
    if (chartView) {
        delete chartView;
    }
}
