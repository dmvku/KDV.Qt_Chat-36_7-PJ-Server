#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "server.h"
#include <QMainWindow>
#include <QDialog>
#include <QListWidgetItem>

namespace Ui
{
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

protected slots:    
    void updateWindow();

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

signals:    
    void netConnection(QString addressIP, quint16 port);
    void addMessage(QString from, QString to, QString message, QString createTime);    

private slots:        
    void on_connectButton_clicked();
    void on_userListWidget_itemClicked(QListWidgetItem *item);
    void setOnlineStatus();
    void addLog(QString log);
    void addItemToChatWindow(QString from, QString to, QString message, QString createTime);
    void addItemToUserWindow(QString name);    
    void on_banPushButton_clicked();
    void on_disconnectPushButton_clicked();
    void on_userOnlyCheckBox_toggled(bool checked);
    void on_privateOnlyCheckBox_toggled(bool checked);

private:
    Ui::MainWindow *ui;

    Server* server_;
    Client* selectedUserPtr_;

    bool isPrivateMessage{ false };
    QString recipient;

    void changeCurrentUserStatus();
    bool onlyForSelectedUser_;
    bool isPrivate_;
};

#endif // MAINWINDOW_H
