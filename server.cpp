#include "server.h"

#include <QTime>
#include <QRegularExpression>

Server::Server(QObject *parent)
    : QObject(parent)
{
    getServerConfig();

    logger_ = new Logger(logFile_);
    netServer_ = new NetServer(netIPAddress_, netPort_);
    onlineClients_ = new QVector<Client>;
    selectedUser_ = new Client();
    chatDB_ = new Database(databaseFile_);

    connect(netServer_, &NetServer::newConnect, this, &Server::addNewConnection);
    connect(netServer_, &NetServer::setDisconnect, this, &Server::disconnectClient);
    connect(netServer_, &NetServer::dataIsReady, this, &Server::dataParsing);
    connect(this, &Server::inSignalLoginUser, this, &Server::loginUser);
    connect(this, &Server::inSignalRegisterUser, this, &Server::registerUser);
    connect(this, &Server::inSignalLogoutUser, this, &Server::logoutClient);
    connect(this, &Server::inSignalAddNewMessage, this, &Server::addNewMessage);
    connect(this, &Server::massMailing, this, &Server::sendMassMailing);
    connect(this, &Server::dataSender, netServer_, &NetServer::dataTransmission);
    connect(netServer_, &NetServer::addNetLog, this, &Server::logTransit);
    connect(chatDB_, &Database::addDatabaseLog, this, &Server::logTransit);
    connect(this, &Server::outAddServerLog, logger_, &Logger::appendLogLine);
}

Server::~Server()
{
    delete chatDB_;
    delete onlineClients_;
    delete selectedUser_;
    delete netServer_;
    delete logger_;
}

void Server::connectToDatabase()
{
    if(chatDB_->checkOpenDatabase())
    {
        usersCache_ = chatDB_->getUsersCache();
        messagesCache_ = chatDB_->getMessagesCache();
    }
}


const QString Server::getServerIPAddress()
{
    return netIPAddress_;
}

quint16 Server::getServerPort()
{
    return netPort_;
}

bool Server::getConnectionStatus()
{
    return isNetworkListen_;
}

short Server::getStatusByName(QString name)
{
    for(auto& user : usersCache_)
    {
        if(user.name_ == name)
        {
            return user.status_;
        }
    }
    return{};
}

QString Server::getNameByUserIDFromCache(int userID)\
{
    for(auto& user : usersCache_)
    {
        if(user.userID_ == userID)
        {
            return user.name_;
        }
    }
    return{};
}

void Server::setSelectedUserByName(QString name)
{
    for(auto& client : *onlineClients_)
    {
        if(client.getName() == name)
        {
            selectedUser_->setSocketDescriptor(client.getSocketDescriptor());
            selectedUser_->setUserID(client.getUserID());
            selectedUser_->setName(name);
            selectedUser_->setStatus(client.getStatus());
            return;
        }
    }

    for(auto& user : usersCache_)
    {
        if(user.name_ == name)
        {
            selectedUser_->setSocketDescriptor(0);
            selectedUser_->setUserID(user.userID_);
            selectedUser_->setName(name);
            selectedUser_->setStatus(user.status_);
        }
    }
}

void Server::clearSelectedUser()
{
    selectedUser_->setSocketDescriptor(0);
    selectedUser_->setUserID(0);
    selectedUser_->setName("");
    selectedUser_->setStatus(0);
}

void Server::hardDisconnectClient(qintptr socketDescriptor)
{
    for (auto it = onlineClients_->begin(); it != onlineClients_->end();)
    {
        if (it->getSocketDescriptor() == socketDescriptor)
        {
            QString name = it->getName();
            QString userID = QString::number(it->getUserID());

            it = onlineClients_->erase(it);

            emit outAddServerLog(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                                 + " ADMIN -X- User \'" + name + ": " + userID
                                 + "\' forcibly disconnected");
            break;
        }
        else
        {
            ++it;
        }
    }

    netServer_->disconnectingClient(socketDescriptor);

    if(selectedUser_->getSocketDescriptor() == socketDescriptor)
    {
        selectedUser_->setSocketDescriptor(0);
    }
}

QString Server::getSocketAddress(qintptr socketDescriptor) const
{
    return netServer_->getSocketAddress(socketDescriptor);
}

QString Server::getSocketPort(qintptr socketDescriptor) const
{
    return netServer_->getSocketPort(socketDescriptor);
}

void Server::addNewConnection(qintptr socketDescriptor)
{
    onlineClients_->push_back({ socketDescriptor, 0, "", 0 });

    QString serverResponse = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                             + " <TCP> <-- [" + getSocketAddress(socketDescriptor) + ":"
                             + getSocketPort(socketDescriptor) + "] Client connected";
    emit outAddServerLog(serverResponse);
}

void Server::loginUser(qintptr socketDescriptor, QString data)
{
    QString serverResponse;

    QString login(data.section(delimiter_, 1, 1));
    QString passwordHash(data.section(delimiter_, 2, 2));

    if (!chatDB_->checkUserByLogin(login))
    {
        serverResponse = QString::number(ServerEnum::Commands::loginError_)
                         + delimiter_ + "User \'" + login + "\' is not found";
    }
    else
    {
        QString databaseResponse = chatDB_->verifyUserAutheticationData(login, passwordHash);

        if (databaseResponse == "")
        {
            serverResponse = QString::number(ServerEnum::Commands::loginError_)
                             + delimiter_ + "Authentication error";            
        }
        else
        {
            QString userID = databaseResponse.section(delimiter_, 0, 0);
            QString name = databaseResponse.section(delimiter_, 1, 1);
            QString status = databaseResponse.section(delimiter_, 2, 2);

            if (status == QString::number(ServerEnum::User_Status::isDeleted_))
            {
                serverResponse = QString::number(ServerEnum::Commands::loginError_)
                                 + delimiter_ + "User \'" + login + "\' has been deleted";
            }
            else
            {
                setClientDataBySocket(socketDescriptor, userID.toInt(), name
                                      , ServerEnum::User_Status::isActive_);

                emit outAddServerLog(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                                     + " <TCP> <-- [" + getSocketAddress(socketDescriptor)
                                     + ":" + getSocketPort(socketDescriptor) + "] User \'"
                                     + userID + ": " + name + "\' is login");

                emit massMailing(QString::number(ServerEnum::Commands::loginUser_)
                                 + delimiter_ + "User \'" + name + "\' is login");

                QString statusInfo = status == QString::number(ServerEnum::User_Status::isBanned_)
                                         ? ". You are banned" : "";
                serverResponse = QString::number(ServerEnum::Commands::loginDone_)
                                 + delimiter_ + name + ": login is successful" + statusInfo
                                 + delimiter_ + userID + delimiter_ + name
                                 + delimiter_ + status;

                sendUsersFromClient(socketDescriptor);
                sendMessagesFromClient(socketDescriptor, userID.toInt());
            }
        }
    }
    emit dataSender(socketDescriptor, serverResponse);
}

void Server::registerUser(qintptr socketDescriptor, QString data)
{
    QString serverResponse;

    QString login(data.section(delimiter_, 1, 1));
    QString name(data.section(delimiter_, 2, 2));
    QString passwordHash(data.section(delimiter_, 3, 3));

    if (chatDB_->checkUserByLogin(login))
    {
        serverResponse = QString::number(ServerEnum::Commands::registerError_)
                         + delimiter_ + "Login \'" + login + "\' is busy";        
    }
    else if (chatDB_->checkUserByName(name))
    {
        serverResponse = QString::number(ServerEnum::Commands::registerError_)
                         + delimiter_ + "Name \'" + name + "\' is busy";        
    }
    else if (!chatDB_->addUser(login, name, passwordHash))
    {
        serverResponse = QString::number(ServerEnum::Commands::registerError_)
                         + delimiter_ + "Registeration error";        
    }
    else
    {        
        int userID = chatDB_->getUserIDByLogin(login);
        short status = ServerEnum::User_Status::isActive_;
        setClientDataBySocket(socketDescriptor, userID, name ,status);

        Database::User tempUser;
        tempUser.userID_ = userID;
        tempUser.name_ = name;
        tempUser.status_ = status;
        usersCache_.push_back(tempUser);

        emit outAddServerLog(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                             + " <TCP> <-- [" + getSocketAddress(socketDescriptor) + ":"
                             + getSocketPort(socketDescriptor) + "] User \'"
                             + QString::number(userID) + ": " + name + "\' is registred");
        emit outSignalAddInUserListWidget(name);

        emit massMailing(QString::number(ServerEnum::Commands::registerUser_)
                         + delimiter_ + QString::number(userID) + delimiter_ + name
                         + delimiter_ + QString::number(status) + delimiter_
                         + "User \'" + name + "\' is registered");

        serverResponse = QString::number(ServerEnum::Commands::registerDone_)
                         + delimiter_ + name + ": registeration is successful"
                         + delimiter_ + QString::number(userID) + delimiter_ + name
                         + delimiter_ + QString::number(status);        

        sendUsersFromClient(socketDescriptor);
        sendMessagesFromClient(socketDescriptor, userID);
    }
    emit dataSender(socketDescriptor, serverResponse);
}

void Server::disconnectClient(qintptr socketDescriptor)
{
    QString name;
    QString userID;
    for (auto it = onlineClients_->begin(); it != onlineClients_->end();)
    {
        if (it->getSocketDescriptor() == socketDescriptor)
        {
            name = it->getName();
            userID = QString::number(it->getUserID());
            it = onlineClients_->erase(it);
            break;
        }
        else
        {
            ++it;
        }
    }

    emit outAddServerLog(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                         + " <TCP> <-- User \'" + name + ": "
                         + userID + "\' is disconnect");

    emit massMailing(QString::number(ServerEnum::Commands::logoutUser_)
                     + delimiter_ + "User \'" + name + "\' is disconnect");
}

void Server::logoutClient(qintptr socketDescriptor)
{    
    for (auto& client : *onlineClients_)
    {
        if (client.getSocketDescriptor() == socketDescriptor)
        {
            QString name = client.getName();

            emit outAddServerLog(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                                 + " <TCP> <-- [" + getSocketAddress(socketDescriptor) + ":"
                                 + getSocketPort(socketDescriptor) + "] User \'" + name + ": "
                                 + QString::number(client.getUserID()) + "\' is logout");

            emit massMailing(QString::number(ServerEnum::Commands::logoutUser_)
                             + delimiter_ + "User \'" + name + "\' is logout");

            client.setUserID(0);
            client.setName("");
            client.setStatus(0);
            break;
        }
    }
}

void Server::addNewMessage(qintptr socketDescriptor, QString data)
{
    QString serverResponse;

    QString from(data.section(delimiter_, 1, 1));
    QString to(data.section(delimiter_, 2, 2));
    QString message(data.section(delimiter_, 3, 3));
    QString createTime(data.section(delimiter_, 4, 4));

    if(chatDB_->addMessage(from, to, message, createTime))
    {
        Database::Message tempMessage;
        tempMessage.from_ = from.toInt();
        tempMessage.to_ = to.toInt();
        tempMessage.message_ = message;
        tempMessage.createTime_ = createTime;
        messagesCache_.push_back(tempMessage);

        emit outAddServerLog(QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                             + " <TCP> <-- [" + getSocketAddress(socketDescriptor) + ":"
                             + getSocketPort(socketDescriptor) + "] add message from User ID \'"
                             + from + "\' to User ID \'" + to + "\'");
        emit outSignalAddInChatListWidget(getNameByUserIDFromCache(tempMessage.from_)
                                          , getNameByUserIDFromCache(tempMessage.to_)
                                          , message
                                          , createTime);

        serverResponse = QString::number(ServerEnum::Commands::sendMessageResult_)
                         + delimiter_ + QString::number(ServerEnum::Commands::sendMessageDone_)
                         + delimiter_ + "The message has been sent";
        emit dataSender(socketDescriptor, serverResponse);

        int recipient = to.toInt();
        if(!recipient)
        {
            emit massMailing(QString::number(ServerEnum::Commands::addMessage_)
                             + data.remove(0, 2));
        }
        else
        {
            quintptr recipientSocketDescriptor = getSocketDescriptorByUserID(recipient);

            serverResponse = QString::number(ServerEnum::Commands::addMessage_)
                             + data.remove(0, 2);

            if(recipientSocketDescriptor == 0)
            {
                emit dataSender(recipientSocketDescriptor, serverResponse);
            }
            emit dataSender(socketDescriptor, serverResponse);
        }
    }
    else
    {
        serverResponse = QString::number(ServerEnum::Commands::sendMessageResult_)
                         + delimiter_ + QString::number(ServerEnum::Commands::sendMessageError_)
                         + delimiter_ + "The message was not sent";
        emit dataSender(socketDescriptor, serverResponse);
    }
}

int Server::getUserIDByName(const QString& name) const
{
    for(auto& client : *onlineClients_)
    {
        if(client.getName() == name)
        {
            return client.getUserID();
        }
    }
    return 0;
}

int Server::getUserIDByLogin(const QString& userLogin) const
{
    for(auto& client : *onlineClients_)
    {
        if(client.getName() == userLogin)
        {
            return client.getUserID();
        }
    }
    return 0;
}

qintptr Server::getSocketDescriptorByUserID(int userID) const
{
    for(auto& client : *onlineClients_)
    {
        if(client.getUserID() == userID)
        {
            return client.getSocketDescriptor();
        }
    }
    return 0;
}

int Server::getUserIDBySocketDescriptor(qintptr socketDescriptor) const
{
    for(auto& client : *onlineClients_)
    {
        if(client.getSocketDescriptor() == socketDescriptor)
        {
            return client.getUserID();
        }
    }
    return 0;
}

QString Server::getNameByUserID(int userID) const
{
    for(auto& client : *onlineClients_)
    {
        if (client.getUserID() == userID)
        {
            return client.getName();
        }
    }
    return nullptr;
}

void Server::sendUsersFromClient(qintptr socketDescriptor)
{
    for(auto& user : usersCache_)
    {
        QString userData = QString::number(ServerEnum::Commands::addUser_)
                           + delimiter_ + QString::number(user.userID_)
                           + delimiter_ + user.name_
                           + delimiter_ + QString::number(user.status_);
        emit dataSender(socketDescriptor, userData);
    }
}

void Server::sendMessagesFromClient(qintptr socketDescriptor, int userID)
{
    for(auto& message : messagesCache_)
    {
        if(message.to_ == allAccountID_
            || message.from_ == userID
            || message.to_ == userID)
        {
            QString sendingMessage = QString::number(ServerEnum::Commands::addMessage_)
                                  + delimiter_ + QString::number(message.from_)
                                  + delimiter_ + QString::number(message.to_)
                                  + delimiter_ + message.message_
                                  + delimiter_ + (message.createTime_)
                                  + delimiter_;
            emit dataSender(socketDescriptor, sendingMessage);
        }
    }
}

void Server::changingUserStatus(const QString& name, short status)
{
    int userID {};
    for(auto& user : usersCache_)
    {
        if(user.name_ == name)
        {
            user.status_ = status;
            userID = user.userID_;
        }
    }

    for(auto& client : *onlineClients_)
    {
        if(client.getName() == name)
        {
            client.setStatus(status);            
        }
    }

    chatDB_->setUserStatus(userID, status);
    selectedUser_->setStatus(status);

    QString sendStatus;
    QString newStatusInfo = status == ServerEnum::User_Status::isBanned_
                            ? "banned" : "unbanned";

    sendStatus = (QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss")
                  + " ADMIN --> " + "User \'" + name + ": "
                  + QString::number(userID) + "\' is %1").arg(newStatusInfo);
    emit outAddServerLog(sendStatus);

    sendStatus = (QString::number(ServerEnum::Commands::setUserStatus_)
                  + delimiter_ + QString::number(userID)
                  + delimiter_ + QString::number(status)
                  + delimiter_ + "User \'" + name + "\' is %1").arg(newStatusInfo);
    emit massMailing(sendStatus);
}

bool Server::startTCPServer(QString addressIP, quint16 port)
{
    isNetworkListen_ = netServer_->startListen(addressIP, port);
    if(isNetworkListen_)
    {
        netIPAddress_ = addressIP;
        netPort_ = port;
        saveServerConfig();
    }
    return isNetworkListen_;
}

void Server::stopTCPServer()
{
    onlineClients_->clear();
    netServer_->stopListen();
    //netServer_->close();

    isNetworkListen_ = false;
}

void Server::sendMassMailing(QString message)
{
    for (auto& client : *onlineClients_)
    {
        emit dataSender(client.getSocketDescriptor(), message);
    }
}

void Server::dataParsing(qintptr socketDescriptor, QString data)
{    
    int command = data.section(delimiter_, 0, 0).toInt();
    switch (command)
    {
    case ServerEnum::Commands::clientLogout_:
        emit inSignalLogoutUser(socketDescriptor);
        break;
    case ServerEnum::Commands::registerUser_:
        emit inSignalRegisterUser(socketDescriptor, data);
        break;
    case ServerEnum::Commands::loginUser_:
        emit inSignalLoginUser(socketDescriptor, data);
        break;
    case ServerEnum::Commands::sendMessage_:
        emit inSignalAddNewMessage(socketDescriptor, data);
        break;
    default:
        break;
    }
}

void Server::logTransit(QString log)
{
    emit outAddServerLog(log);
}

Client *Server::getSelectedUserPtr()
{
    return selectedUser_;
}

void Server::updateUserListWindow()
{
    for(auto& user : usersCache_)
    {
        emit outSignalAddInUserListWidget(user.name_);
    }
}

void Server::updateChatListWindow()
{
    for(auto& message : messagesCache_)
    {
        emit outSignalAddInChatListWidget(getNameByUserIDFromCache(message.from_)
                                          ,getNameByUserIDFromCache(message.to_)
                                          , message.message_
                                          , message.createTime_);
    }
}

void Server::setClientDataBySocket(qintptr socketDescriptor, int userID, QString name, short status)
{
    for(auto& client : *onlineClients_)
    {
        if(client.getSocketDescriptor() == socketDescriptor)
        {
            client.setUserID(userID);
            client.setName(name);
            client.setStatus(status);            
        }
    }
}

void Server::getServerConfig()
{
    QFile fileStream(configFile_);
    QTextStream line(&fileStream);

    fileStream.open(QIODevice::ReadOnly);
    if (!fileStream.isOpen())
    {
        saveServerConfig();
        return;
    }

    while (!line.atEnd()) {
        QString parameter = line.readLine();

        if (parameter.section(':', 0, 0) == "serverIPAddress")
        {
            QString addressIP = parameter.section(':', 1, 1);
            if (checkAddressIP(addressIP))
            {
                netIPAddress_ = addressIP;
            }
        }
        else if (parameter.section(':', 0, 0) == "serverPort")
        {
            quint16 port = (parameter.section(':', 1, 1)).toUShort();
            if (checkPort(port))
            {
                netPort_ = port;
            }
        }
        else if (parameter.section(':', 0, 0) == "serverLogFile")
        {
            logFile_ = parameter.section(':', 1, 1);
        }
        else if (parameter.section(':', 0, 0) == "serverDBFile")
        {
            databaseFile_ = parameter.section(':', 1, 1);
        }
    }
    fileStream.close();
    saveServerConfig();
}

void Server::saveServerConfig()
{
    QFile fileStream(configFile_);
    QTextStream stream(&fileStream);

    fileStream.open(QIODeviceBase::Truncate | QIODeviceBase::WriteOnly);
    if (!fileStream.isOpen())
    {
        return;
    }

    QString saveData = "serverIPAddress:" + netIPAddress_ + "\n"
                       + "serverPort:" + QString::number(netPort_) + "\n"
                       + "serverLogFile:" + logFile_  + "\n"
                       + "serverDBFile:" + databaseFile_;

    stream << saveData;
    fileStream.close();
}

bool Server::checkPort(quint16 port)
{
    int minPort{ 1024 };
    return !(port < minPort || port > USHRT_MAX);
}

bool Server::checkAddressIP(const QString& addressIP)
{
    static const QRegularExpression ipRegex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
                                            "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    return (ipRegex.match(addressIP).hasMatch() || addressIP == "localhost");
}

void Server::setIsSelectedUserOnly(bool isForSelectedUserOnly)
{
    isSelectedUserOnly_ = isForSelectedUserOnly;
}

void Server::setIsPrivateChat(bool isPrivate)
{
    isPrivateChat_ = isPrivate;
}

void Server::showChatWindow()
{
    int selectedUserID = selectedUser_->getUserID();

    for(auto& message : messagesCache_)
    {
        if(isPrivateChat_ && message.to_ == 0)
        {
            continue;
        }

        if(isSelectedUserOnly_)
        {
            if(isPrivateChat_)
            {
                if(!((message.from_ == selectedUserID && message.to_ != 0) ||
                      (message.from_ != 0 && message.to_ == selectedUserID)))
                {
                    continue;
                }
            }
            else
            {
                if(!((message.from_ == selectedUserID)||(message.to_ == selectedUserID)))
                {
                    continue;
                }
            }
        }

        emit outSignalAddInChatListWidget(getNameByUserIDFromCache(message.from_)
                                          ,getNameByUserIDFromCache(message.to_)
                                          , message.message_
                                          , message.createTime_);
    }
}
