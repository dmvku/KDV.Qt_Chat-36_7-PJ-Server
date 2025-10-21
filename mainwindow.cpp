#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QMessageBox>
#include <QWidget>
#include <QInputDialog>
#include <QTimer>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);    
    ui->disconnectPushButton->setEnabled(false);
    this->setWindowTitle("Chat (server)");

    server_ = new Server;

    QTimer::singleShot(50, this, &MainWindow::isWindowLoaded);
}

MainWindow::~MainWindow()
{
    delete server_;    
    delete ui;
}

void MainWindow::isWindowLoaded()
{
    selectedUserPtr_ = server_->getSelectedUserPtr();
    server_->connectToDatabase();
    server_->updateUserListWindow();
    server_->updateChatListWindow();
    ui->IPAddressValue->setText(server_->getServerIPAddress());
    ui->portValue->setText(QString::number(server_->getServerPort()));
    disconnect(server_, &Server::outAddServerLog, this, &MainWindow::addLog);
    disconnect(server_, &Server::outSignalAddInUserListWidget, this, &MainWindow::addItemToUserWindow);
    disconnect(server_, &Server::outSignalAddInChatListWidget, this, &MainWindow::addItemToChatWindow);
    connect(server_, &Server::outAddServerLog, this, &MainWindow::addLog);
    connect(server_, &Server::outSignalAddInUserListWidget, this, &MainWindow::addItemToUserWindow);
    connect(server_, &Server::outSignalAddInChatListWidget, this, &MainWindow::addItemToChatWindow);
}

void MainWindow::on_connectButton_clicked()
{
    if(!server_->getConnectionStatus())
    {
        if(!server_->checkAddressIP(ui->IPAddressValue->text()))
        {
            QMessageBox::critical(this, "Error", "Invalid IP address");
            ui->IPAddressValue->setText(server_->getServerIPAddress());
            return;
        }
        else if(!server_->checkPort(ui->portValue->text().toUShort()))
        {
            QMessageBox::critical(this, "Error", "Invalid port");
            ui->portValue->setText(QString::number(server_->getServerPort()));
            return;
        }

        if(!server_->startTCPServer(ui->IPAddressValue->text(), ui->portValue->text().toUShort()))
        {
            QMessageBox::critical(this, "Error" ,"Server don't ctarted");
            return;
        }
    }
    else
    {
        server_->stopTCPServer();
        QMessageBox::information(this, "Warning", "Connection close");
    }
    setOnlineStatus();
}

void MainWindow::on_userListWidget_itemClicked(QListWidgetItem *item)
{
    QString currentUserName = selectedUserPtr_->getName();
    QString selectedUserName = item->text();

    if(item->text() == currentUserName && item->isSelected())
    {
        item->setSelected(false);
        server_->clearSelectedUser();        
        ui->chatUsersLable->setText("Users");
        ui->userOnlyCheckBox->setEnabled(false);
        ui->banPushButton->setText("Ban");
        ui->banPushButton->setEnabled(false);
        ui->disconnectPushButton->setText("Disconnect");
        ui->disconnectPushButton->setEnabled(false);        
        isPrivateMessage = false;
    }
    else
    {
        item->setSelected(true);
        server_->setSelectedUserByName(selectedUserName);
        selectedUserPtr_->getStatus() == ServerEnum::User_Status::isBanned_
            ? ui->banPushButton->setText("Unban " + selectedUserName)
            : ui->banPushButton->setText("Ban " + selectedUserName);
        selectedUserPtr_->getSocketDescriptor() != 0
            ? ui->disconnectPushButton->setText("Disconnect " + selectedUserName)
            : ui->disconnectPushButton->setText("Disconnect");
        ui->userOnlyCheckBox->setEnabled(true);        
        ui->chatUsersLable->setText(selectedUserName);        
        ui->disconnectPushButton->setEnabled(selectedUserPtr_->getSocketDescriptor());
        isPrivateMessage = true;
    }

    if(isPrivate_ || onlyForSelectedUser_)
    {
        ui->chatWindow->clear();
        server_->showChatWindow();
    }
}

void MainWindow::setOnlineStatus()
{
    bool connectionStatus = server_->getConnectionStatus();

    if(connectionStatus)
    {
        ui->informationLabel->setText("<font color=green>Connected</font>");
        ui->connectButton->setStyleSheet("color: red;");
        ui->connectButton->setText("Disconnect");        
    }
    else
    {        
        ui->informationLabel->setText("<font color=red>Disconnected</font>");
        ui->connectButton->setStyleSheet("color: green;");
        ui->connectButton->setText("Connect");
    }
}

void MainWindow::addLog(QString log)
{
    ui->logTextEdit->append(log);
}

void MainWindow::addItemToChatWindow(QString from, QString to, QString message, QString createTime)
{   
    ui->chatWindow->append(QString("<font color=\"purple\">%1</font>  "
                              "<font color=\"blue\">%2</font> write "
                              "<font color=\"blue\">%3</font>: %4")
                               .arg(createTime, from, to == "0" ? "" : to, message));
    }

void MainWindow::addItemToUserWindow(QString name)
{    
    ui->userListWidget->addItem(name);
}

void MainWindow::changeCurrentUserStatus()
{
    if(selectedUserPtr_->getStatus() == ServerEnum::User_Status::isBanned_)
    {
        server_->changingUserStatus(selectedUserPtr_->getName()
                                    , ServerEnum::User_Status::isActive_);
        ui->banPushButton->setText("Ban " + selectedUserPtr_->getName());
    }
    else
    {
        server_->changingUserStatus(selectedUserPtr_->getName()
                                    , ServerEnum::User_Status::isBanned_);
        ui->banPushButton->setText("Unban " + selectedUserPtr_->getName());
    }
}

void MainWindow::updateWindow()
{
    ui->chatWindow->clear();
    ui->userListWidget->clear();
    server_->updateUserListWindow();
    server_->updateChatListWindow();
}

void MainWindow::on_banPushButton_clicked()
{
    changeCurrentUserStatus();
}

void MainWindow::on_disconnectPushButton_clicked()
{
    server_->hardDisconnectClient(selectedUserPtr_->getSocketDescriptor());
    ui->disconnectPushButton->setText("Disconnect");
    ui->disconnectPushButton->setEnabled(false);
}

void MainWindow::on_userOnlyCheckBox_toggled(bool checked)
{
    if(checked)
    {
        onlyForSelectedUser_ = true;
        server_->setIsSelectedUserOnly(true);
        ui->chatWindow->clear();
        server_->showChatWindow();
    }
    else
    {
        onlyForSelectedUser_ = false;
        server_->setIsSelectedUserOnly(false);
        ui->chatWindow->clear();
        server_->showChatWindow();
    }
}


void MainWindow::on_privateOnlyCheckBox_toggled(bool checked)
{
    if(checked)
    {
        isPrivate_ = true;
        server_->setIsPrivateChat(true);
        ui->chatWindow->clear();
        server_->showChatWindow();
    }
    else
    {
        isPrivate_ = false;
        server_->setIsPrivateChat(false);
        ui->chatWindow->clear();
        server_->showChatWindow();
    }
}

