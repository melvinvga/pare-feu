#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QVector>
#include <QMap>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QTimer *monTimer;
    int ancienNb;
    QMap<QString,QVector<long>> mapIp;

private slots:
    void update();
    void debloquerIp();
};

#endif // MAINWINDOW_H
