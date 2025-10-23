#include <QApplication>
#include "mainwindow.h"
#include <QTimer>

int main(int argc, char* argv[])
{
    QApplication newApp(argc, argv);
    MainWindow newWindow;
    newWindow.show();
    
    return newApp.exec();
}
