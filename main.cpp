#include "mainwindow.h"
#include <QApplication>
#include <QDebug>
#include <QTimer>
#include <QFile>
#include <iostream>
using namespace std;
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
